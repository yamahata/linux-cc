// SPDX-License-Identifier: GPL-2.0-only

#include "../lib/x86_64/tdx.h"
#include <processor.h>
#include <sys/wait.h>

#define NR_MIGRATE_TEST_VMS 3
#define SHARED_GPA_BASE 0x80000000

#define CHECK_IO(RUN, PORT, SIZE, DIR)							\
	do {										\
		TEST_ASSERT((RUN)->exit_reason == KVM_EXIT_IO,				\
			    "Got exit_reason other than KVM_EXIT_IO: %u (%s)\n",	\
			    run->exit_reason,						\
			    exit_reason_str(run->exit_reason));				\
											\
		TEST_ASSERT(((RUN)->exit_reason == KVM_EXIT_IO) &&			\
			    ((RUN)->io.port == (PORT)) &&				\
			    ((RUN)->io.size == (SIZE)) &&				\
			    ((RUN)->io.direction == (DIR)),				\
			    "Got an unexpected IO exit values: %u (%s) %d %d %d\n",	\
			    (RUN)->exit_reason, exit_reason_str((RUN)->exit_reason),	\
			    (RUN)->io.port, (RUN)->io.size, (RUN)->io.direction);	\
	} while (0)

#define CHECK_GUEST_FAILURE(RUN)							\
	do {										\
		if (run->exit_reason == KVM_EXIT_SYSTEM_EVENT)				\
			TEST_FAIL("Guest reported error. error code: %lld (0x%llx)\n",	\
				  run->system_event.flags, run->system_event.flags);	\
	} while (0)

#define CHECK_GUEST_COMPLETION(RUN)								\
	(TEST_ASSERT(										\
		((RUN)->exit_reason == KVM_EXIT_IO) &&						\
		((RUN)->io.port == TDX_SUCCESS_PORT) &&						\
		((RUN)->io.size == 4) &&							\
		((RUN)->io.direction == TDX_IO_WRITE),						\
		"Unexpected exit values while waiting for test complition: %u (%s) %d %d %d\n",	\
		(RUN)->exit_reason, exit_reason_str((RUN)->exit_reason),			\
		(RUN)->io.port, (RUN)->io.size, (RUN)->io.direction))

/*
 * Verify that the TDX  is supported by the KVM.
 */
bool is_tdx_enabled(void)
{
	return !!(kvm_check_cap(KVM_CAP_VM_TYPES) & BIT(KVM_X86_TDX_VM));
}

/*
 * There might be multiple tests we are running and if one test fails, it will
 * prevent the subsequent tests to run due to how tests are failing with
 * TEST_ASSERT function. The run_in_new_process function will run a test in a
 * new process context and wait for it to finish or fail to prevent TEST_ASSERT
 * to kill the main testing process.
 */
void run_in_new_process(void (*func)(void))
{
	if (fork() == 0) {
		func();
		exit(0);
	}
	wait(NULL);
}

static int __tdx_migrate_from(int dst_fd, int src_fd)
{
	struct kvm_enable_cap cap = {
		.cap = KVM_CAP_VM_COPY_ENC_CONTEXT_FROM,
		.args = { src_fd }
	};

	return ioctl(dst_fd, KVM_ENABLE_CAP, &cap);
}


static void tdx_migrate_from(int dst_fd, int src_fd)
{
	int ret;

	ret = __tdx_migrate_from(dst_fd, src_fd);
	TEST_ASSERT(!ret, "Migration failed, ret: %d, errno: %d\n", ret, errno);
}

static void test_tdx_migrate_empty_vm(void)
{
	struct kvm_vm *src_vm;
	struct kvm_vm *dst_vms[NR_MIGRATE_TEST_VMS];
	int i, ret;

	printf("Verifying migration of an empty VM:\n");

	/* Create a TD VM with no memory.*/
	src_vm = __vm_create(VM_MODE_DEFAULT, 0, O_RDWR, KVM_X86_TDX_VM);
	initialize_td(src_vm);
	finalize_td_memory(src_vm);

	for (i = 0; i < NR_MIGRATE_TEST_VMS; ++i) {
		dst_vms[i] = __vm_create(VM_MODE_DEFAULT, 0, O_RDWR, KVM_X86_TDX_VM);
		initialize_td(dst_vms[i]);
	}

	/* Initial migration from the src to the first dst. */
	tdx_migrate_from(dst_vms[0]->fd, src_vm->fd);

	for (i = 1; i < NR_MIGRATE_TEST_VMS; i++)
		tdx_migrate_from(dst_vms[i]->fd, dst_vms[i - 1]->fd);

	/* Migrate the guest back to the original VM. */
	ret = __tdx_migrate_from(src_vm->fd, dst_vms[NR_MIGRATE_TEST_VMS - 1]->fd);
	TEST_ASSERT(ret == -1 && errno == EIO,
		    "VM that was migrated from should be dead. ret %d, errno: %d\n", ret,
		    errno);

	kvm_vm_free(src_vm);
	for (i = 0; i < NR_MIGRATE_TEST_VMS; ++i)
		kvm_vm_free(dst_vms[i]);

	printf("\t ... PASSED\n");
}

TDX_GUEST_FUNCTION(guest)
{
	uint64_t data;

	data = 1;
	tdvmcall_io(TDX_TEST_PORT, 1, TDX_IO_WRITE, &data);

	data++;
	tdvmcall_io(TDX_TEST_PORT, 1, TDX_IO_WRITE, &data);

	tdvmcall_success();
}

static void test_tdx_migrate_vm_with_private_memory(void)
{
	struct kvm_vm *src_vm;
	struct kvm_vm *dst_vm;
	struct kvm_run *run;
	uint32_t data;

	printf("Verifying migration of VM with private memory:\n");

	/* Create a TD VM with no memory.*/
	src_vm = __vm_create(VM_MODE_DEFAULT, 0, O_RDWR, KVM_X86_TDX_VM);
	initialize_td(src_vm);
	vm_vcpu_add_tdx(src_vm, 0);
	prepare_source_image(src_vm, guest,
			     TDX_FUNCTION_SIZE(guest), 0);
	finalize_td_memory(src_vm);

	dst_vm = __vm_create(VM_MODE_DEFAULT, 0, O_RDWR, KVM_X86_TDX_VM);
	initialize_td(dst_vm);
	vm_vcpu_add_tdx(dst_vm, 0);

	/* Initial migration from the src to the first dst. */
	tdx_migrate_from(dst_vm->fd, src_vm->fd);

	kvm_vm_free(src_vm);

	run = vcpu_state(dst_vm, 0);

	vcpu_run(dst_vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_IO(run, TDX_TEST_PORT, 1, TDX_IO_WRITE);
	data = *(uint8_t *)((void *)run + run->io.data_offset);
	ASSERT_EQ(data, 1);

	vcpu_run(dst_vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_IO(run, TDX_TEST_PORT, 1, TDX_IO_WRITE);
	data = *(uint8_t *)((void *)run + run->io.data_offset);
	ASSERT_EQ(data, 2);

	vcpu_run(dst_vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_GUEST_COMPLETION(run);

	kvm_vm_free(dst_vm);

	printf("\t ... PASSED\n");
}

static void test_tdx_migrate_running_vm(void)
{
	struct kvm_vm *src_vm;
	struct kvm_vm *dst_vm;
	struct kvm_run *run;
	uint32_t data;

	printf("Verifying migration of a running VM:\n");

	/* Create a TD VM with no memory.*/
	src_vm = __vm_create(VM_MODE_DEFAULT, 0, O_RDWR, KVM_X86_TDX_VM);
	initialize_td(src_vm);
	vm_vcpu_add_tdx(src_vm, 0);
	prepare_source_image(src_vm, guest,
			     TDX_FUNCTION_SIZE(guest), 0);
	finalize_td_memory(src_vm);

	dst_vm = __vm_create(VM_MODE_DEFAULT, 0, O_RDWR, KVM_X86_TDX_VM);
	initialize_td(dst_vm);
	vm_vcpu_add_tdx(dst_vm, 0);

	run = vcpu_state(src_vm, 0);

	vcpu_run(src_vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_IO(run, TDX_TEST_PORT, 1, TDX_IO_WRITE);
	data = *(uint8_t *)((void *)run + run->io.data_offset);
	ASSERT_EQ(data, 1);

	tdx_migrate_from(dst_vm->fd, src_vm->fd);

	kvm_vm_free(src_vm);

	run = vcpu_state(dst_vm, 0);

	vcpu_run(dst_vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_IO(run, TDX_TEST_PORT, 1, TDX_IO_WRITE);
	data = *(uint8_t *)((void *)run + run->io.data_offset);
	ASSERT_EQ(data, 2);

	vcpu_run(dst_vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_GUEST_COMPLETION(run);

	kvm_vm_free(dst_vm);

	printf("\t ... PASSED\n");
}

TDX_GUEST_FUNCTION(guest_with_shared_mem)
{
	uint64_t *private_data, *shared_data;
	uint64_t gpa_shared_mask;
	uint64_t gva_shared_mask;
	uint64_t shared_gpa;
	uint64_t gpa_width;
	uint64_t failed_gpa;
	uint64_t data;
	uint64_t ret;
	uint64_t err;

	gva_shared_mask = BIT_ULL(TDX_GUEST_VIRT_SHARED_BIT);
	shared_gpa = SHARED_GPA_BASE;

	/* Get physical shared mask */
	err = tdcall_vp_info(&gpa_width, 0, 0, 0, 0, 0);
	if (err)
		tdvmcall_fatal(err);
	gpa_shared_mask = BIT_ULL(gpa_width - 1);

	/* TODO: Remove once shared memory mapping bug is fixed. */
	ret = tdvmcall_map_gpa(shared_gpa, PAGE_SIZE, &failed_gpa);
	if (ret)
		tdvmcall_fatal(ret);

	/* Map gpa as shared. */
	ret = tdvmcall_map_gpa(shared_gpa | gpa_shared_mask, PAGE_SIZE,
			       &failed_gpa);
	if (ret)
		tdvmcall_fatal(ret);

	shared_data = (uint64_t *)(shared_gpa | gva_shared_mask);
	private_data = &data;

	*private_data = 1;
	tdvmcall_io(TDX_TEST_PORT, 4, TDX_IO_WRITE, private_data);

	(*private_data)++;
	tdvmcall_io(TDX_TEST_PORT, 4, TDX_IO_WRITE, private_data);

	(*shared_data) = 11;
	tdvmcall_io(TDX_TEST_PORT, 4, TDX_IO_WRITE, shared_data);

	tdvmcall_success();
}

static void test_tdx_migrate_vm_with_shared_mem(void)
{
	uint32_t private_data, shared_data;
	struct kvm_vm *src_vm;
	struct kvm_vm *dst_vm;
	struct kvm_run *run;
	uint64_t hva;

	printf("Verifying migration of a VM with shared memory:\n");

	/* Create a TD VM with no memory.*/
	src_vm = __vm_create(VM_MODE_DEFAULT, 0, O_RDWR, KVM_X86_TDX_VM);
	initialize_td(src_vm);
	vm_vcpu_add_tdx(src_vm, 0);
	hva = add_shared_mem_region(src_vm, SHARED_GPA_BASE, 1);
	printf("\t ... hva: 0x%lx\n", hva);
	prepare_source_image(src_vm, guest_with_shared_mem,
			     TDX_FUNCTION_SIZE(guest_with_shared_mem), 0);
	finalize_td_memory(src_vm);

	dst_vm = __vm_create(VM_MODE_DEFAULT, 0, O_RDWR, KVM_X86_TDX_VM);
	initialize_td(dst_vm);
	vm_vcpu_add_tdx(dst_vm, 0);
	hva = add_shared_mem_region(dst_vm, SHARED_GPA_BASE, 1);
	printf("\t ... hva: 0x%lx\n", hva);

	run = vcpu_state(src_vm, 0);

	vcpu_run(src_vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_IO(run, TDX_TEST_PORT, 4, TDX_IO_WRITE);
	private_data = *(uint32_t *)((void *)run + run->io.data_offset);
	ASSERT_EQ(private_data, 1);

	tdx_migrate_from(dst_vm->fd, src_vm->fd);

	kvm_vm_free(src_vm);

	run = vcpu_state(dst_vm, 0);

	vcpu_run(dst_vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_IO(run, TDX_TEST_PORT, 4, TDX_IO_WRITE);
	private_data = *(uint32_t *)((void *)run + run->io.data_offset);
	ASSERT_EQ(private_data, 2);

	vcpu_run(dst_vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_IO(run, TDX_TEST_PORT, 4, TDX_IO_WRITE);
	shared_data = *(uint32_t *)((void *)run + run->io.data_offset);
	ASSERT_EQ(shared_data, 11);

	vcpu_run(dst_vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_GUEST_COMPLETION(run);

	kvm_vm_free(dst_vm);

	printf("\t ... PASSED\n");
}

int main(int argc, char *argv[])
{
	if (!is_tdx_enabled()) {
		print_skip("TDX is not supported by the KVM");
		exit(KSFT_SKIP);
	}

	run_in_new_process(&test_tdx_migrate_empty_vm);
	run_in_new_process(&test_tdx_migrate_vm_with_private_memory);
	run_in_new_process(&test_tdx_migrate_running_vm);
	run_in_new_process(&test_tdx_migrate_vm_with_shared_mem);

	return 0;
}
