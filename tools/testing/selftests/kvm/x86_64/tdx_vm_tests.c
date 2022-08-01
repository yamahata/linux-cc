// SPDX-License-Identifier: GPL-2.0-only

#include "asm/kvm.h"
#include "linux/kernel.h"
#include <bits/stdint-uintn.h>
#include <fcntl.h>
#include <kvm_util.h>
#include <limits.h>
#include <linux/kvm.h>
#include <processor.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <test_util.h>
#include <time.h>
#include <unistd.h>
#include "../lib/kvm_util_internal.h"
#include "../lib/x86_64/tdx.h"

#define CHECK_IO(RUN, PORT, SIZE, DIR)						\
	TEST_ASSERT((RUN)->exit_reason == KVM_EXIT_IO,				\
		    "Got exit_reason other than KVM_EXIT_IO: %u (%s)\n",	\
		    run->exit_reason,						\
		    exit_reason_str(run->exit_reason));				\
										\
	TEST_ASSERT(((RUN)->exit_reason == KVM_EXIT_IO) &&			\
			    ((RUN)->io.port == (PORT)) &&			\
			    ((RUN)->io.size == (SIZE)) &&			\
			    ((RUN)->io.direction == (DIR)),			\
		    "Got an unexpected IO exit values: %u (%s) %d %d %d\n",	\
		    (RUN)->exit_reason, exit_reason_str((RUN)->exit_reason),	\
		    (RUN)->io.port, (RUN)->io.size, (RUN)->io.direction);

#define CHECK_MMIO(RUN, ADDR, SIZE, DIR)					\
	TEST_ASSERT((RUN)->exit_reason == KVM_EXIT_MMIO,			\
		    "Got exit_reason other than KVM_EXIT_MMIO: %u (%s)\n",	\
		    run->exit_reason,						\
		    exit_reason_str(run->exit_reason));				\
										\
	TEST_ASSERT(((RUN)->exit_reason == KVM_EXIT_MMIO) &&			\
			    ((RUN)->mmio.phys_addr == (ADDR)) &&		\
			    ((RUN)->mmio.len == (SIZE)) &&			\
			    ((RUN)->mmio.is_write == (DIR)),			\
		    "Got an unexpected MMIO exit values: %u (%s) %llu %d %d\n",	\
		    (RUN)->exit_reason, exit_reason_str((RUN)->exit_reason),	\
		    (RUN)->mmio.phys_addr, (RUN)->mmio.len, (RUN)->mmio.is_write);

#define CHECK_GUEST_FAILURE(RUN)                                               \
	if (run->exit_reason == KVM_EXIT_SYSTEM_EVENT)                         \
		TEST_FAIL("Guest reported error. error code: %lld (0x%llx)\n", \
			  run->system_event.flags, run->system_event.flags);

#define CHECK_GUEST_COMPLETION(RUN)										\
TEST_ASSERT(													\
		((RUN)->exit_reason == KVM_EXIT_IO) &&								\
			((RUN)->io.port == TDX_SUCCESS_PORT) &&							\
			((RUN)->io.size == 4) &&								\
		((RUN)->io.direction == TDX_IO_WRITE),								\
		"Got an unexpected IO exit values while waiting for test complition: %u (%s) %d %d %d\n",	\
		(RUN)->exit_reason, exit_reason_str((RUN)->exit_reason),					\
		(RUN)->io.port, (RUN)->io.size, (RUN)->io.direction);

/*
 * Define a filter which denies all MSR access except the following:
 * MTTR_BASE_0: Allow read/write access
 * MTTR_BASE_1: Allow read access
 * MTTR_BASE_2: Allow write access
 */
static u64 allow_bits = 0xFFFFFFFFFFFFFFFF;
#define MTTR_BASE_0 (0x200)
#define MTTR_BASE_1 (0x202)
#define MTTR_BASE_2 (0x204)
struct kvm_msr_filter test_filter = {
	.flags = KVM_MSR_FILTER_DEFAULT_DENY,
	.ranges = {
		{
			.flags = KVM_MSR_FILTER_READ |
				 KVM_MSR_FILTER_WRITE,
			.nmsrs = 1,
			.base = MTTR_BASE_0,
			.bitmap = (uint8_t*)&allow_bits,
		}, {
			.flags = KVM_MSR_FILTER_READ,
			.nmsrs = 1,
			.base = MTTR_BASE_1,
			.bitmap = (uint8_t*)&allow_bits,
		}, {
			.flags = KVM_MSR_FILTER_WRITE,
			.nmsrs = 1,
			.base = MTTR_BASE_2,
			.bitmap = (uint8_t*)&allow_bits,
		},
	},
};

#define MMIO_VALID_ADDRESS (TDX_GUEST_MAX_NR_PAGES * PAGE_SIZE + 1)

static uint64_t read_64bit_from_guest_vcpu(struct kvm_vm *vm, struct kvm_run *run,
				       uint32_t vcpuid, uint64_t port)
{
	uint32_t lo, hi;
	uint64_t res;

	CHECK_IO(run, port, 4, TDX_IO_WRITE);
	lo = *(uint32_t *)((void *)run + run->io.data_offset);

	vcpu_run(vm, vcpuid);

	CHECK_IO(run, port, 4, TDX_IO_WRITE);
	hi = *(uint32_t *)((void *)run + run->io.data_offset);

	res = hi;
	res = (res << 32) | lo;
	return res;
}

static uint64_t read_64bit_from_guest(struct kvm_vm *vm, struct kvm_run *run,
				      uint64_t port)
{
	return read_64bit_from_guest_vcpu(vm, run, 0, port);
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

/*
 * Verify that the TDX  is supported by the KVM.
 */
bool is_tdx_enabled(void)
{
	return !!(kvm_check_cap(KVM_CAP_VM_TYPES) & BIT(KVM_X86_TDX_VM));
}

/*
 * Find a specific CPUID entry.
 */
static struct kvm_cpuid_entry2 *
find_cpuid_entry(struct tdx_cpuid_data cpuid_data, uint32_t function,
		 uint32_t index)
{
	struct kvm_cpuid_entry2 *e;
	int i;

	for (i = 0; i < cpuid_data.cpuid.nent; i++) {
		e = &cpuid_data.entries[i];

		if (e->function == function &&
		    (e->index == index ||
		     !(e->flags & KVM_CPUID_FLAG_SIGNIFCANT_INDEX)))
			return e;
	}
	return NULL;
}

/*
 * Do a dummy io exit to verify that the TD has been initialized correctly and
 * guest can run some code inside.
 */
TDX_GUEST_FUNCTION(guest_dummy_exit)
{
	tdvmcall_success();
}

/*
 * TD lifecycle test will create a TD which runs a dumy IO exit to verify that
 * the guest TD has been created correctly.
 */
void verify_td_lifecycle(void)
{
	struct kvm_vm *vm;
	struct kvm_run *run;

	printf("Verifying TD lifecycle:\n");
	/* Create a TD VM with no memory.*/
	vm = __vm_create(VM_MODE_DEFAULT, 0, O_RDWR, KVM_X86_TDX_VM);

	/* Allocate TD guest memory and initialize the TD.*/
	initialize_td(vm);

	/* Initialize the TD vcpu and copy the test code to the guest memory.*/
	vm_vcpu_add_tdx(vm, 0);

	/* Setup and initialize VM memory */
	prepare_source_image(vm, guest_dummy_exit,
			     TDX_FUNCTION_SIZE(guest_dummy_exit), 0);
	finalize_td_memory(vm);

	run = vcpu_state(vm, 0);
	vcpu_run(vm, 0);
	CHECK_GUEST_COMPLETION(run);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

/*
 * Verifies IO functionality by writing a |value| to a predefined port.
 * Verifies that the read value is |value| + 1 from the same port.
 * If all the tests are passed then write a value to port TDX_TEST_PORT
 */
TDX_GUEST_FUNCTION(guest_io_exit)
{
	uint64_t data_out, data_in, delta;
	uint64_t ret;

	data_out = 0xAB;

	ret = tdvmcall_io(TDX_TEST_PORT, 1, TDX_IO_WRITE, &data_out);
	if (ret)
		tdvmcall_fatal(ret);

	ret = tdvmcall_io(TDX_TEST_PORT, 1, TDX_IO_READ, &data_in);
	if (ret)
		tdvmcall_fatal(ret);

	delta = data_in - data_out;
	if (delta != 1)
		tdvmcall_fatal(ret);

	tdvmcall_success();
}

void verify_td_ioexit(void)
{
	struct kvm_vm *vm;
	struct kvm_run *run;
	uint32_t port_data;

	printf("Verifying TD IO Exit:\n");
	/* Create a TD VM with no memory.*/
	vm = __vm_create(VM_MODE_DEFAULT, 0, O_RDWR, KVM_X86_TDX_VM);

	/* Allocate TD guest memory and initialize the TD.*/
	initialize_td(vm);

	/* Initialize the TD vcpu and copy the test code to the guest memory.*/
	vm_vcpu_add_tdx(vm, 0);

	/* Setup and initialize VM memory */
	prepare_source_image(vm, guest_io_exit,
			     TDX_FUNCTION_SIZE(guest_io_exit), 0);
	finalize_td_memory(vm);

	run = vcpu_state(vm, 0);

	/* Wait for guest to do a IO write */
	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_IO(run, TDX_TEST_PORT, 1, TDX_IO_WRITE);
	port_data = *(uint8_t *)((void *)run + run->io.data_offset);

	printf("\t ... IO WRITE: OK\n");
	/*
	 * Wait for the guest to do a IO read. Provide the previos written data
	 * + 1 back to the guest
	 */
	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_IO(run, TDX_TEST_PORT, 1, TDX_IO_READ);

	*(uint8_t *)((void *)run + run->io.data_offset) = port_data + 1;

	printf("\t ... IO READ: OK\n");
	/*
	 * Wait for the guest to complete execution successfuly. The read value
	 * is checked within the guest.
	 */
	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_GUEST_COMPLETION(run);

	printf("\t ... IO verify read/write values: OK\n");
	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

/*
 * Verifies CPUID functionality by reading CPUID values in guest. The guest
 * will then send the values to userspace using an IO write to be checked
 * against the expected values.
 */
TDX_GUEST_FUNCTION(guest_code_cpuid)
{
	uint64_t err;
	uint32_t eax, ebx, edx, ecx;

	// Read CPUID leaf 0x1.
	eax = 1;
	ecx = 0;
	cpuid(&eax, &ebx, &ecx, &edx);

	err = tdvm_report_to_user_space(ebx);
	if (err)
		tdvmcall_fatal(err);

	err = tdvm_report_to_user_space(ecx);
	if (err)
		tdvmcall_fatal(err);

	tdvmcall_success();
}

void verify_td_cpuid(void)
{
	int ret;
	struct kvm_vm *vm;
	struct kvm_run *run;
	uint32_t ebx, ecx;
	struct tdx_cpuid_data cpuid_data;
	struct kvm_cpuid_entry2 *cpuid_entry;
	uint32_t guest_clflush_line_size;
	uint32_t guest_max_addressable_ids, host_max_addressable_ids;
	uint32_t guest_sse3_enabled;
	uint32_t guest_fma_enabled;
	uint32_t guest_initial_apic_id;

	printf("Verifying TD CPUID:\n");
	/* Create a TD VM with no memory.*/
	vm = __vm_create(VM_MODE_DEFAULT, 0, O_RDWR, KVM_X86_TDX_VM);

	/* Allocate TD guest memory and initialize the TD.*/
	initialize_td(vm);

	/* Initialize the TD vcpu and copy the test code to the guest memory.*/
	vm_vcpu_add_tdx(vm, 0);

	/* Setup and initialize VM memory */
	prepare_source_image(vm, guest_code_cpuid,
			     TDX_FUNCTION_SIZE(guest_code_cpuid), 0);
	finalize_td_memory(vm);

	run = vcpu_state(vm, 0);

	/* Wait for guest to report ebx value */
	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_IO(run, TDX_DATA_REPORT_PORT, 4, TDX_IO_WRITE);
	ebx = *(uint32_t *)((void *)run + run->io.data_offset);

	/* Wait for guest to report either ecx value or error */
	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_IO(run, TDX_DATA_REPORT_PORT, 4, TDX_IO_WRITE);
	ecx = *(uint32_t *)((void *)run + run->io.data_offset);

	/* Wait for guest to complete execution */
	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_GUEST_COMPLETION(run);

	/* Verify the CPUID values we got from the guest. */
	printf("\t ... Verifying CPUID values from guest\n");

	/* Get KVM CPUIDs for reference */
	memset(&cpuid_data, 0, sizeof(cpuid_data));
	cpuid_data.cpuid.nent = KVM_MAX_CPUID_ENTRIES;
	ret = ioctl(vm->kvm_fd, KVM_GET_SUPPORTED_CPUID, &cpuid_data);
	TEST_ASSERT(!ret, "KVM_GET_SUPPORTED_CPUID failed\n");
	cpuid_entry = find_cpuid_entry(cpuid_data, 1, 0);
	TEST_ASSERT(cpuid_entry, "CPUID entry missing\n");

	host_max_addressable_ids = (cpuid_entry->ebx >> 16) & 0xFF;

	guest_sse3_enabled = ecx & 0x1;  // Native
	guest_clflush_line_size = (ebx >> 8) & 0xFF;  // Fixed
	guest_max_addressable_ids = (ebx >> 16) & 0xFF;  // As Configured
	guest_fma_enabled = (ecx >> 12) & 0x1;  // As Configured (if Native)
	guest_initial_apic_id = (ebx >> 24) & 0xFF;  // Calculated

	ASSERT_EQ(guest_sse3_enabled, 1);
	ASSERT_EQ(guest_clflush_line_size, 8);
	ASSERT_EQ(guest_max_addressable_ids, host_max_addressable_ids);

	/* TODO: This only tests the native value. To properly test
	 * "As Configured (if Native)" we need to override this value
	 * in the TD params
	 */
	ASSERT_EQ(guest_fma_enabled, 1);

	/* TODO: guest_initial_apic_id is calculated based on the number of
	 * VCPUs in the TD. From the spec: "Virtual CPU index, starting from 0
	 * and allocated sequentially on each successful TDH.VP.INIT"
	 * To test non-trivial values we either need a TD with multiple VCPUs
	 * or to pick a different calculated value.
	 */
	ASSERT_EQ(guest_initial_apic_id, 0);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

/*
 * Verifies CPUID TDVMCALL functionality.
 * The guest will then send the values to userspace using an IO write to be
 * checked against the expected values.
 */
TDX_GUEST_FUNCTION(guest_code_cpuid_tdcall)
{
	uint64_t err;
	uint32_t eax, ebx, ecx, edx;

	// Read CPUID leaf 0x1 from host.
	err = tdvmcall_cpuid(/*eax=*/1, /*ecx=*/0, &eax, &ebx, &ecx, &edx);
	if (err)
		tdvmcall_fatal(err);

	err = tdvm_report_to_user_space(eax);
	if (err)
		tdvmcall_fatal(err);
	
	err = tdvm_report_to_user_space(ebx);
	if (err)
		tdvmcall_fatal(err);
	
	err = tdvm_report_to_user_space(ecx);
	if (err)
		tdvmcall_fatal(err);
	
	err = tdvm_report_to_user_space(edx);
	if (err)
		tdvmcall_fatal(err);

	tdvmcall_success();
}

void verify_td_cpuid_tdcall(void)
{
	int ret;
	struct kvm_vm *vm;
	struct kvm_run *run;
	uint32_t eax, ebx, ecx, edx;
	struct tdx_cpuid_data cpuid_data;
	struct kvm_cpuid_entry2 *cpuid_entry;

	printf("Verifying TD CPUID TDVMCALL:\n");
	/* Create a TD VM with no memory.*/
	vm = __vm_create(VM_MODE_DEFAULT, 0, O_RDWR, KVM_X86_TDX_VM);

	/* Allocate TD guest memory and initialize the TD.*/
	initialize_td(vm);

	/* Initialize the TD vcpu and copy the test code to the guest memory.*/
	vm_vcpu_add_tdx(vm, 0);

	/* Setup and initialize VM memory */
	prepare_source_image(vm, guest_code_cpuid_tdcall,
			     TDX_FUNCTION_SIZE(guest_code_cpuid_tdcall), 0);
	finalize_td_memory(vm);

	run = vcpu_state(vm, 0);

	/* Wait for guest to report CPUID values */
	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_IO(run, TDX_DATA_REPORT_PORT, 4, TDX_IO_WRITE);
	eax = *(uint32_t *)((void *)run + run->io.data_offset);

	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_IO(run, TDX_DATA_REPORT_PORT, 4, TDX_IO_WRITE);
	ebx = *(uint32_t *)((void *)run + run->io.data_offset);

	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_IO(run, TDX_DATA_REPORT_PORT, 4, TDX_IO_WRITE);
	ecx = *(uint32_t *)((void *)run + run->io.data_offset);

	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_IO(run, TDX_DATA_REPORT_PORT, 4, TDX_IO_WRITE);
	edx = *(uint32_t *)((void *)run + run->io.data_offset);

	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_GUEST_COMPLETION(run);

	/* Get KVM CPUIDs for reference */
	memset(&cpuid_data, 0, sizeof(cpuid_data));
	cpuid_data.cpuid.nent = KVM_MAX_CPUID_ENTRIES;
	ret = ioctl(vm->kvm_fd, KVM_GET_SUPPORTED_CPUID, &cpuid_data);
	TEST_ASSERT(!ret, "KVM_GET_SUPPORTED_CPUID failed\n");
	cpuid_entry = find_cpuid_entry(cpuid_data, 1, 0);
	TEST_ASSERT(cpuid_entry, "CPUID entry missing\n");

	ASSERT_EQ(cpuid_entry->eax, eax);
	// Mask lapic ID when comparing ebx.
	ASSERT_EQ(cpuid_entry->ebx & ~0xFF000000, ebx & ~0xFF000000);
	ASSERT_EQ(cpuid_entry->ecx, ecx);
	ASSERT_EQ(cpuid_entry->edx, edx);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

/*
 * Verifies CPUID TDVMCALL functionality when using invalid leaf number.
 */
TDX_GUEST_FUNCTION(guest_code_cpuid_tdcall_invalid_leaf)
{
	uint64_t err;
	uint32_t eax, ebx, ecx, edx;

	// Read invalid CPUID which should return VMCALL_INVALID_OPERAND.
	err = tdvmcall_cpuid(/*eax=*/0x42, /*ecx=*/0, &eax, &ebx, &ecx, &edx);
	if (err)
		tdvmcall_fatal(err);

	tdvmcall_success();
}

void verify_td_cpuid_tdcall_invalid_leaf(void)
{
	struct kvm_vm *vm;
	struct kvm_run *run;

	printf("Verifying TD CPUID TDVMCALL with invalid CPUID leaf:\n");
	/* Create a TD VM with no memory.*/
	vm = __vm_create(VM_MODE_DEFAULT, 0, O_RDWR, KVM_X86_TDX_VM);

	/* Allocate TD guest memory and initialize the TD.*/
	initialize_td(vm);

	/* Initialize the TD vcpu and copy the test code to the guest memory.*/
	vm_vcpu_add_tdx(vm, 0);

	/* Setup and initialize VM memory */
	prepare_source_image(vm, guest_code_cpuid_tdcall_invalid_leaf,
			     TDX_FUNCTION_SIZE(guest_code_cpuid_tdcall_invalid_leaf), 0);
	finalize_td_memory(vm);

	run = vcpu_state(vm, 0);

	vcpu_run(vm, 0);
	ASSERT_EQ(run->exit_reason, KVM_EXIT_SYSTEM_EVENT);
	ASSERT_EQ(run->system_event.flags, TDX_VMCALL_INVALID_OPERAND);

	vcpu_run(vm, 0);
	CHECK_GUEST_COMPLETION(run);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

/*
 * Verifies get_td_vmcall_info functionality.
 */
TDX_GUEST_FUNCTION(guest_code_get_td_vmcall_info)
{
	uint64_t err;
	uint64_t r11, r12, r13, r14;

	err = tdvmcall_get_td_vmcall_info(&r11, &r12, &r13, &r14);
	if (err)
		tdvmcall_fatal(err);

	err = tdvm_report_64bit_to_user_space(r11);
	if (err)
		tdvmcall_fatal(err);

	err = tdvm_report_64bit_to_user_space(r12);
	if (err)
		tdvmcall_fatal(err);

	err = tdvm_report_64bit_to_user_space(r13);
	if (err)
		tdvmcall_fatal(err);

	err = tdvm_report_64bit_to_user_space(r14);
	if (err)
		tdvmcall_fatal(err);

	tdvmcall_success();
}

void verify_get_td_vmcall_info(void)
{
	struct kvm_vm *vm;
	struct kvm_run *run;
	uint64_t r11, r12, r13, r14;

	printf("Verifying TD get vmcall info:\n");
	/* Create a TD VM with no memory.*/
	vm = __vm_create(VM_MODE_DEFAULT, 0, O_RDWR, KVM_X86_TDX_VM);

	/* Allocate TD guest memory and initialize the TD.*/
	initialize_td(vm);

	/* Initialize the TD vcpu and copy the test code to the guest memory.*/
	vm_vcpu_add_tdx(vm, 0);

	/* Setup and initialize VM memory */
	prepare_source_image(vm, guest_code_get_td_vmcall_info,
			     TDX_FUNCTION_SIZE(guest_code_get_td_vmcall_info),
			     0);
	finalize_td_memory(vm);

	run = vcpu_state(vm, 0);

	/* Wait for guest to report r11 value */
	vcpu_run(vm, 0);
	/* TODO: This check fails since get_td_vmcall_info is not implemented
	 * in KVM yet.
	 */
	CHECK_GUEST_FAILURE(run);
	r11 = read_64bit_from_guest(vm, run, TDX_DATA_REPORT_PORT);

	/* Wait for guest to report r12 value */
	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	r12 = read_64bit_from_guest(vm, run, TDX_DATA_REPORT_PORT);

	/* Wait for guest to report r13 value */
	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	r13 = read_64bit_from_guest(vm, run, TDX_DATA_REPORT_PORT);

	/* Wait for guest to report r14 value */
	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	r14 = read_64bit_from_guest(vm, run, TDX_DATA_REPORT_PORT);

	ASSERT_EQ(r11, 0);
	ASSERT_EQ(r12, 0);
	ASSERT_EQ(r13, 0);
	ASSERT_EQ(r14, 0);

	/* Wait for guest to complete execution */
	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_GUEST_COMPLETION(run);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

/*
 * Verifies TDX_REPORT_FATAL_ERROR functionality.
 */
TDX_GUEST_FUNCTION(guest_code_report_fatal_error)
{
	uint64_t err;
	err = 0xBAADF00D00000000;

	if (err)
		tdvmcall_fatal(err);

	tdvmcall_success();
}

void verify_report_fatal_error(void)
{
	struct kvm_vm *vm;
	struct kvm_run *run;

	printf("Verifying report_fatal_error:\n");
	/* Create a TD VM with no memory.*/
	vm = __vm_create(VM_MODE_DEFAULT, 0, O_RDWR, KVM_X86_TDX_VM);

	/* Allocate TD guest memory and initialize the TD.*/
	initialize_td(vm);

	/* Initialize the TD vcpu and copy the test code to the guest memory.*/
	vm_vcpu_add_tdx(vm, 0);

	/* Setup and initialize VM memory */
	prepare_source_image(vm, guest_code_report_fatal_error,
			     TDX_FUNCTION_SIZE(guest_code_report_fatal_error),
			     0);
	finalize_td_memory(vm);

	run = vcpu_state(vm, 0);

	vcpu_run(vm, 0);
	ASSERT_EQ(run->exit_reason, KVM_EXIT_SYSTEM_EVENT);
	ASSERT_EQ(run->system_event.flags, 0xBAADF00D00000000);

	vcpu_run(vm, 0);
	CHECK_GUEST_COMPLETION(run);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

/*
 * Verifies IO functionality by writing values of different sizes
 * to the host.
 */
TDX_GUEST_FUNCTION(guest_io_writes)
{
	uint64_t byte_1 = 0xAB;
	uint64_t byte_2 = 0xABCD;
	uint64_t byte_4 = 0xFFABCDEF;
	uint64_t ret;

	ret = tdvmcall_io(TDX_TEST_PORT, 1, TDX_IO_WRITE, &byte_1);
	if (ret)
		tdvmcall_fatal(ret);

	ret = tdvmcall_io(TDX_TEST_PORT, 2, TDX_IO_WRITE, &byte_2);
	if (ret)
		tdvmcall_fatal(ret);

	ret = tdvmcall_io(TDX_TEST_PORT, 4, TDX_IO_WRITE, &byte_4);
	if (ret)
		tdvmcall_fatal(ret);

	// Write an invalid number of bytes.
	ret = tdvmcall_io(TDX_TEST_PORT, 5, TDX_IO_WRITE, &byte_4);
	if (ret)
		tdvmcall_fatal(ret);

	tdvmcall_success();
}

void verify_guest_writes(void)
{
	struct kvm_vm *vm;
	struct kvm_run *run;
	uint8_t byte_1;
	uint16_t byte_2;
	uint32_t byte_4;

	printf("Verifying guest writes:\n");
	/* Create a TD VM with no memory.*/
	vm = __vm_create(VM_MODE_DEFAULT, 0, O_RDWR, KVM_X86_TDX_VM);

	/* Allocate TD guest memory and initialize the TD.*/
	initialize_td(vm);

	/* Initialize the TD vcpu and copy the test code to the guest memory.*/
	vm_vcpu_add_tdx(vm, 0);

	/* Setup and initialize VM memory */
	prepare_source_image(vm, guest_io_writes,
			     TDX_FUNCTION_SIZE(guest_io_writes), 0);
	finalize_td_memory(vm);

	run = vcpu_state(vm, 0);

	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_IO(run, TDX_TEST_PORT, 1, TDX_IO_WRITE);
	byte_1 = *(uint8_t *)((void *)run + run->io.data_offset);

	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_IO(run, TDX_TEST_PORT, 2, TDX_IO_WRITE);
	byte_2 = *(uint16_t *)((void *)run + run->io.data_offset);

	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_IO(run, TDX_TEST_PORT, 4, TDX_IO_WRITE);
	byte_4 = *(uint32_t *)((void *)run + run->io.data_offset);

	ASSERT_EQ(byte_1, 0xAB);
	ASSERT_EQ(byte_2, 0xABCD);
	ASSERT_EQ(byte_4, 0xFFABCDEF);

	vcpu_run(vm, 0);
	ASSERT_EQ(run->exit_reason, KVM_EXIT_SYSTEM_EVENT);
	ASSERT_EQ(run->system_event.flags, TDX_VMCALL_INVALID_OPERAND);

	vcpu_run(vm, 0);
	CHECK_GUEST_COMPLETION(run);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

/*
 * Verifies IO functionality by reading values of different sizes
 * from the host.
 */
TDX_GUEST_FUNCTION(guest_io_reads)
{
	uint64_t data;
	uint64_t ret;

	ret = tdvmcall_io(TDX_TEST_PORT, 1, TDX_IO_READ, &data);
	if (ret)
		tdvmcall_fatal(ret);
	if (data != 0xAB)
		tdvmcall_fatal(1);

	ret = tdvmcall_io(TDX_TEST_PORT, 2, TDX_IO_READ, &data);
	if (ret)
		tdvmcall_fatal(ret);
	if (data != 0xABCD)
		tdvmcall_fatal(2);

	ret = tdvmcall_io(TDX_TEST_PORT, 4, TDX_IO_READ, &data);
	if (ret)
		tdvmcall_fatal(ret);
	if (data != 0xFFABCDEF)
		tdvmcall_fatal(4);

	// Read an invalid number of bytes.
	ret = tdvmcall_io(TDX_TEST_PORT, 5, TDX_IO_READ, &data);
	if (ret)
		tdvmcall_fatal(ret);

	tdvmcall_success();
}

void verify_guest_reads(void)
{
	struct kvm_vm *vm;
	struct kvm_run *run;

	printf("Verifying guest reads:\n");
	/* Create a TD VM with no memory.*/
	vm = __vm_create(VM_MODE_DEFAULT, 0, O_RDWR, KVM_X86_TDX_VM);

	/* Allocate TD guest memory and initialize the TD.*/
	initialize_td(vm);

	/* Initialize the TD vcpu and copy the test code to the guest memory.*/
	vm_vcpu_add_tdx(vm, 0);

	/* Setup and initialize VM memory */
	prepare_source_image(vm, guest_io_reads,
			     TDX_FUNCTION_SIZE(guest_io_reads), 0);
	finalize_td_memory(vm);

	run = vcpu_state(vm, 0);

	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_IO(run, TDX_TEST_PORT, 1, TDX_IO_READ);
	*(uint8_t *)((void *)run + run->io.data_offset) = 0xAB;

	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_IO(run, TDX_TEST_PORT, 2, TDX_IO_READ);
	*(uint16_t *)((void *)run + run->io.data_offset) = 0xABCD;

	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_IO(run, TDX_TEST_PORT, 4, TDX_IO_READ);
	*(uint32_t *)((void *)run + run->io.data_offset) = 0xFFABCDEF;

	vcpu_run(vm, 0);
	ASSERT_EQ(run->exit_reason, KVM_EXIT_SYSTEM_EVENT);
	ASSERT_EQ(run->system_event.flags, TDX_VMCALL_INVALID_OPERAND);

	vcpu_run(vm, 0);
	CHECK_GUEST_COMPLETION(run);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

/*
 * Verifies MSR read functionality.
 */
TDX_GUEST_FUNCTION(guest_msr_read)
{
	uint64_t data;
	uint64_t ret;

	ret = tdvmcall_rdmsr(MTTR_BASE_0, &data);
	if (ret)
		tdvmcall_fatal(ret);

	ret = tdvm_report_64bit_to_user_space(data);
	if (ret)
		tdvmcall_fatal(ret);

	ret = tdvmcall_rdmsr(MTTR_BASE_1, &data);
	if (ret)
		tdvmcall_fatal(ret);

	ret = tdvm_report_64bit_to_user_space(data);
	if (ret)
		tdvmcall_fatal(ret);

	/* We expect this call to fail since MTTR_BASE_2 is write only */
	ret = tdvmcall_rdmsr(MTTR_BASE_2, &data);
	if (ret) {
		ret = tdvm_report_64bit_to_user_space(ret);
		if (ret)
			tdvmcall_fatal(ret);
	}

	tdvmcall_success();
}

void verify_guest_msr_reads(void)
{
	struct kvm_vm *vm;
	struct kvm_run *run;
	int ret;
	uint64_t data;

	struct kvm_enable_cap cap = {
		.cap = KVM_CAP_X86_USER_SPACE_MSR,
		.args[0] = KVM_MSR_EXIT_REASON_FILTER,
	};

	printf("Verifying guest msr reads:\n");

	/* Create a TD VM with no memory.*/
	vm = __vm_create(VM_MODE_DEFAULT, 0, O_RDWR, KVM_X86_TDX_VM);

	/* Set explicit MSR filter map to control access to the MSR registers
	 * used in the test.
	 */
	printf("\t ... Setting test MSR filter\n");
	ret = kvm_check_cap(KVM_CAP_X86_USER_SPACE_MSR);
	TEST_ASSERT(ret, "KVM_CAP_X86_USER_SPACE_MSR is unavailable");
	vm_enable_cap(vm, &cap);

	ret = kvm_check_cap(KVM_CAP_X86_MSR_FILTER);
	TEST_ASSERT(ret, "KVM_CAP_X86_MSR_FILTER is unavailable");

	ret = ioctl(vm->fd, KVM_X86_SET_MSR_FILTER, &test_filter);
	TEST_ASSERT(ret == 0,
		    "KVM_X86_SET_MSR_FILTER failed, ret: %i errno: %i (%s)",
		    ret, errno, strerror(errno));

	/* Allocate TD guest memory and initialize the TD.*/
	initialize_td(vm);

	/* Initialize the TD vcpu and copy the test code to the guest memory.*/
	vm_vcpu_add_tdx(vm, 0);

	/* Setup and initialize VM memory */
	prepare_source_image(vm, guest_msr_read,
			     TDX_FUNCTION_SIZE(guest_msr_read), 0);
	finalize_td_memory(vm);

	printf("\t ... Setting test MTTR values\n");
	/* valid values for mttr type are 0, 1, 4, 5, 6 */
	vcpu_set_msr(vm, 0, MTTR_BASE_0, 4);
	vcpu_set_msr(vm, 0, MTTR_BASE_1, 5);
	vcpu_set_msr(vm, 0, MTTR_BASE_2, 6);

	run = vcpu_state(vm, 0);

	printf("\t ... Running guest\n");
	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	data = read_64bit_from_guest(vm, run, TDX_DATA_REPORT_PORT);
	ASSERT_EQ(data, 4);

	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	data = read_64bit_from_guest(vm, run, TDX_DATA_REPORT_PORT);
	ASSERT_EQ(data, 5);

	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	data = read_64bit_from_guest(vm, run, TDX_DATA_REPORT_PORT);
	ASSERT_EQ(data, TDX_VMCALL_INVALID_OPERAND);

	vcpu_run(vm, 0);
	CHECK_GUEST_COMPLETION(run);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

/*
 * Verifies MSR write functionality.
 */
TDX_GUEST_FUNCTION(guest_msr_write)
{
	uint64_t ret;

	ret = tdvmcall_wrmsr(MTTR_BASE_0, 4);
	if (ret)
		tdvmcall_fatal(ret);

	/* We expect this call to fail since MTTR_BASE_1 is read only */
	ret = tdvmcall_wrmsr(MTTR_BASE_1, 5);
	if (ret) {
		ret = tdvm_report_64bit_to_user_space(ret);
		if (ret)
			tdvmcall_fatal(ret);
	}

	ret = tdvmcall_wrmsr(MTTR_BASE_2, 6);
	if (ret)
		tdvmcall_fatal(ret);

	tdvmcall_success();
}

void verify_guest_msr_writes(void)
{
	struct kvm_vm *vm;
	struct kvm_run *run;
	int ret;
	uint64_t data;

	struct kvm_enable_cap cap = {
		.cap = KVM_CAP_X86_USER_SPACE_MSR,
		.args[0] = KVM_MSR_EXIT_REASON_FILTER,
	};

	printf("Verifying guest msr writes:\n");

	/* Create a TD VM with no memory.*/
	vm = __vm_create(VM_MODE_DEFAULT, 0, O_RDWR, KVM_X86_TDX_VM);

	/* Set explicit MSR filter map to control access to the MSR registers
	 * used in the test.
	 */
	printf("\t ... Setting test MSR filter\n");
	ret = kvm_check_cap(KVM_CAP_X86_USER_SPACE_MSR);
	TEST_ASSERT(ret, "KVM_CAP_X86_USER_SPACE_MSR is unavailable");
	vm_enable_cap(vm, &cap);

	ret = kvm_check_cap(KVM_CAP_X86_MSR_FILTER);
	TEST_ASSERT(ret, "KVM_CAP_X86_MSR_FILTER is unavailable");

	ret = ioctl(vm->fd, KVM_X86_SET_MSR_FILTER, &test_filter);
	TEST_ASSERT(ret == 0,
		    "KVM_X86_SET_MSR_FILTER failed, ret: %i errno: %i (%s)",
		    ret, errno, strerror(errno));

	/* Allocate TD guest memory and initialize the TD.*/
	initialize_td(vm);

	/* Initialize the TD vcpu and copy the test code to the guest memory.*/
	vm_vcpu_add_tdx(vm, 0);

	/* Setup and initialize VM memory */
	prepare_source_image(vm, guest_msr_write,
			     TDX_FUNCTION_SIZE(guest_msr_write), 0);
	finalize_td_memory(vm);

	run = vcpu_state(vm, 0);

	printf("\t ... Running guest\n");
	/* Only the write to MTTR_BASE_1 should trigger an exit */
	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	data = read_64bit_from_guest(vm, run, TDX_DATA_REPORT_PORT);
	ASSERT_EQ(data, TDX_VMCALL_INVALID_OPERAND);

	vcpu_run(vm, 0);
	CHECK_GUEST_COMPLETION(run);

	printf("\t ... Verifying MTTR values writen by guest\n");

	ASSERT_EQ(vcpu_get_msr(vm, 0, MTTR_BASE_0), 4);
	ASSERT_EQ(vcpu_get_msr(vm, 0, MTTR_BASE_1), 0);
	ASSERT_EQ(vcpu_get_msr(vm, 0, MTTR_BASE_2), 6);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

/*
 * Verifies HLT functionality.
 */
TDX_GUEST_FUNCTION(guest_hlt)
{
	uint64_t ret;
	uint64_t interrupt_blocked_flag;

	interrupt_blocked_flag = 0;
	ret = tdvmcall_hlt(interrupt_blocked_flag);
	if (ret)
		tdvmcall_fatal(ret);

	tdvmcall_success();
}

void _verify_guest_hlt(int signum);

void wake_me(int interval)
{
	struct sigaction action;

	action.sa_handler = _verify_guest_hlt;
	sigemptyset (&action.sa_mask);
	action.sa_flags = 0;

	TEST_ASSERT(sigaction (SIGALRM, &action , NULL) == 0,
		    "Could not set the alarm handler!");

	alarm(interval);
}

void _verify_guest_hlt(int signum)
{
	static struct kvm_vm *vm = NULL;
	struct kvm_run *run = NULL;

	/*
	 * This function will also be called by SIGALRM handler to check the
	 * vCPU MP State. If vm has been initialized, then we are in the signal
	 * handler. Check the MP state and let the guest run again.
	 * */
	if (vm != NULL) {
		struct kvm_mp_state mp_state;

		vcpu_get_mp_state(vm, 0, &mp_state);
		ASSERT_EQ(mp_state.mp_state, KVM_MP_STATE_HALTED);

		/* Let the guest to run and finish the test.*/
		mp_state.mp_state = KVM_MP_STATE_RUNNABLE;
		vcpu_set_mp_state(vm, 0, &mp_state);
		return;
	}

	printf("Verifying HLT:\n");

	/* Create a TD VM with no memory.*/
	vm = __vm_create(VM_MODE_DEFAULT, 0, O_RDWR, KVM_X86_TDX_VM);

	/* Allocate TD guest memory and initialize the TD.*/
	initialize_td(vm);

	/* Initialize the TD vcpu and copy the test code to the guest memory.*/
	vm_vcpu_add_tdx(vm, 0);

	/* Setup and initialize VM memory */
	prepare_source_image(vm, guest_hlt,
			     TDX_FUNCTION_SIZE(guest_hlt), 0);
	finalize_td_memory(vm);

	run = vcpu_state(vm, 0);

	printf("\t ... Running guest\n");

	/* Wait 1 second for guest to execute HLT */
	wake_me(1);
	vcpu_run(vm, 0);

	CHECK_GUEST_COMPLETION(run);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

void verify_guest_hlt(void)
{
	_verify_guest_hlt(0);
}

TDX_GUEST_FUNCTION(guest_mmio_reads)
{
	uint64_t data;
	uint64_t ret;

	ret = tdvmcall_mmio_read(MMIO_VALID_ADDRESS, 1, &data);
	if (ret)
		tdvmcall_fatal(ret);
	if (data != 0x12)
		tdvmcall_fatal(1);

	ret = tdvmcall_mmio_read(MMIO_VALID_ADDRESS, 2, &data);
	if (ret)
		tdvmcall_fatal(ret);
	if (data != 0x1234)
		tdvmcall_fatal(2);

	ret = tdvmcall_mmio_read(MMIO_VALID_ADDRESS, 4, &data);
	if (ret)
		tdvmcall_fatal(ret);
	if (data != 0x12345678)
		tdvmcall_fatal(4);

	ret = tdvmcall_mmio_read(MMIO_VALID_ADDRESS, 8, &data);
	if (ret)
		tdvmcall_fatal(ret);
	if (data != 0x1234567890ABCDEF)
		tdvmcall_fatal(8);

	// Read an invalid number of bytes.
	ret = tdvmcall_mmio_read(MMIO_VALID_ADDRESS, 10, &data);
	if (ret)
		tdvmcall_fatal(ret);

	tdvmcall_success();
}

/*
 * Varifies guest MMIO reads.
 */
void verify_mmio_reads(void)
{
	struct kvm_vm *vm;
	struct kvm_run *run;

	printf("Verifying TD MMIO reads:\n");
	/* Create a TD VM with no memory.*/
	vm = __vm_create(VM_MODE_DEFAULT, 0, O_RDWR, KVM_X86_TDX_VM);

	/* Allocate TD guest memory and initialize the TD.*/
	initialize_td(vm);

	/* Initialize the TD vcpu and copy the test code to the guest memory.*/
	vm_vcpu_add_tdx(vm, 0);

	/* Setup and initialize VM memory */
	prepare_source_image(vm, guest_mmio_reads,
			     TDX_FUNCTION_SIZE(guest_mmio_reads), 0);
	finalize_td_memory(vm);

	run = vcpu_state(vm, 0);

	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_MMIO(run, MMIO_VALID_ADDRESS, 1, TDX_MMIO_READ);
	*(uint8_t *)run->mmio.data = 0x12;

	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_MMIO(run, MMIO_VALID_ADDRESS, 2, TDX_MMIO_READ);
	*(uint16_t *)run->mmio.data = 0x1234;

	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_MMIO(run, MMIO_VALID_ADDRESS, 4, TDX_MMIO_READ);
	*(uint32_t *)run->mmio.data = 0x12345678;

	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_MMIO(run, MMIO_VALID_ADDRESS, 8, TDX_MMIO_READ);
	*(uint64_t *)run->mmio.data = 0x1234567890ABCDEF;

	vcpu_run(vm, 0);
	ASSERT_EQ(run->exit_reason, KVM_EXIT_SYSTEM_EVENT);
	ASSERT_EQ(run->system_event.flags, TDX_VMCALL_INVALID_OPERAND);

	vcpu_run(vm, 0);
	CHECK_GUEST_COMPLETION(run);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

TDX_GUEST_FUNCTION(guest_mmio_writes)
{
	uint64_t ret;

	ret = tdvmcall_mmio_write(MMIO_VALID_ADDRESS, 1, 0x12);
	if (ret)
		tdvmcall_fatal(ret);

	ret = tdvmcall_mmio_write(MMIO_VALID_ADDRESS, 2, 0x1234);
	if (ret)
		tdvmcall_fatal(ret);

	ret = tdvmcall_mmio_write(MMIO_VALID_ADDRESS, 4, 0x12345678);
	if (ret)
		tdvmcall_fatal(ret);

	ret = tdvmcall_mmio_write(MMIO_VALID_ADDRESS, 8, 0x1234567890ABCDEF);
	if (ret)
		tdvmcall_fatal(ret);

	// Write accross page boundry.
	ret = tdvmcall_mmio_write(PAGE_SIZE - 1, 8, 0);
	if (ret)
		tdvmcall_fatal(ret);

	tdvmcall_success();
}

/*
 * Varifies guest MMIO writes.
 */
void verify_mmio_writes(void)
{
	struct kvm_vm *vm;
	struct kvm_run *run;
	uint8_t byte_1;
	uint16_t byte_2;
	uint32_t byte_4;
	uint64_t byte_8;

	printf("Verifying TD MMIO writes:\n");
	/* Create a TD VM with no memory.*/
	vm = __vm_create(VM_MODE_DEFAULT, 0, O_RDWR, KVM_X86_TDX_VM);

	/* Allocate TD guest memory and initialize the TD.*/
	initialize_td(vm);

	/* Initialize the TD vcpu and copy the test code to the guest memory.*/
	vm_vcpu_add_tdx(vm, 0);

	/* Setup and initialize VM memory */
	prepare_source_image(vm, guest_mmio_writes,
			     TDX_FUNCTION_SIZE(guest_mmio_writes), 0);
	finalize_td_memory(vm);

	run = vcpu_state(vm, 0);

	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_MMIO(run, MMIO_VALID_ADDRESS, 1, TDX_MMIO_WRITE);
	byte_1 = *(uint8_t *)(run->mmio.data);

	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_MMIO(run, MMIO_VALID_ADDRESS, 2, TDX_MMIO_WRITE);
	byte_2 = *(uint16_t *)(run->mmio.data);

	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_MMIO(run, MMIO_VALID_ADDRESS, 4, TDX_MMIO_WRITE);
	byte_4 = *(uint32_t *)(run->mmio.data);

	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_MMIO(run, MMIO_VALID_ADDRESS, 8, TDX_MMIO_WRITE);
	byte_8 = *(uint64_t *)(run->mmio.data);

	ASSERT_EQ(byte_1, 0x12);
	ASSERT_EQ(byte_2, 0x1234);
	ASSERT_EQ(byte_4, 0x12345678);
	ASSERT_EQ(byte_8, 0x1234567890ABCDEF);

	vcpu_run(vm, 0);
	ASSERT_EQ(run->exit_reason, KVM_EXIT_SYSTEM_EVENT);
	ASSERT_EQ(run->system_event.flags, TDX_VMCALL_INVALID_OPERAND);

	vcpu_run(vm, 0);
	CHECK_GUEST_COMPLETION(run);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

/*
 * TDG.VP.INFO call from the guest. Verify the right values are returned
 */
void verify_tdcall_vp_info(void)
{
	struct kvm_vm *vm;
	struct kvm_run *run;
	uint64_t rcx, rdx, r8, r9, r10, r11;
	uint32_t num_vcpus, max_vcpus;
	uint64_t attributes;
	uint32_t vcpus_ctr, i;
	struct tdx_cpuid_data cpuid_data;
	struct kvm_cpuid_entry2 *cpuid_entry;
	int max_pa = -1;
	int ret;

	printf("Verifying TDG.VP.INFO call:\n");
	/* Create a TD VM with no memory.*/
	vm = __vm_create(VM_MODE_DEFAULT, 0, O_RDWR, KVM_X86_TDX_VM);

	/* Setting attributes parameter used by TDH.MNG.INIT to 0x50000000 */
	attributes = TDX_TDPARAM_ATTR_SEPT_VE_DISABLE_BIT |
		     TDX_TDPARAM_ATTR_PKS_BIT;

	/* Allocate TD guest memory and initialize the TD.*/
	initialize_td_with_attributes(vm, attributes);

	/* Create 2 vCPUs*/
	for (vcpus_ctr = 0; vcpus_ctr < 2; vcpus_ctr++)
		vm_vcpu_add_tdx(vm, vcpus_ctr);

	/* Setup and initialize VM memory */
	prepare_source_image(vm, guest_tdcall_vp_info,
			     TDX_FUNCTION_SIZE(guest_tdcall_vp_info), 0);
	finalize_td_memory(vm);

	/* Get KVM CPUIDs for reference */
	memset(&cpuid_data, 0, sizeof(cpuid_data));
	cpuid_data.cpuid.nent = KVM_MAX_CPUID_ENTRIES;
	ret = ioctl(vm->kvm_fd, KVM_GET_SUPPORTED_CPUID, &cpuid_data);
	TEST_ASSERT(!ret, "KVM_GET_SUPPORTED_CPUID failed\n");
	cpuid_entry = find_cpuid_entry(cpuid_data, 0x80000008, 0);
	TEST_ASSERT(cpuid_entry, "CPUID entry missing\n");
	max_pa = cpuid_entry->eax & 0xff;

	for (i = 0; i < vcpus_ctr; i++) {
		run = vcpu_state(vm, i);

		/* Wait for guest to report rcx value */
		vcpu_run(vm, i);
		CHECK_GUEST_FAILURE(run);
		rcx = read_64bit_from_guest_vcpu(vm, run, i,
						 TDX_DATA_REPORT_PORT);

		/* Wait for guest to report rdx value */
		vcpu_run(vm, i);
		CHECK_GUEST_FAILURE(run);
		rdx = read_64bit_from_guest_vcpu(vm, run, i,
						 TDX_DATA_REPORT_PORT);

		/* Wait for guest to report r8 value */
		vcpu_run(vm, i);
		CHECK_GUEST_FAILURE(run);
		r8 = read_64bit_from_guest_vcpu(vm, run, i,
						TDX_DATA_REPORT_PORT);

		/* Wait for guest to report r9 value */
		vcpu_run(vm, i);
		CHECK_GUEST_FAILURE(run);
		r9 = read_64bit_from_guest_vcpu(vm, run, i,
						TDX_DATA_REPORT_PORT);

		/* Wait for guest to report r10 value */
		vcpu_run(vm, i);
		CHECK_GUEST_FAILURE(run);
		r10 = read_64bit_from_guest_vcpu(vm, run, i,
						 TDX_DATA_REPORT_PORT);

		/* Wait for guest to report r11 value */
		vcpu_run(vm, i);
		CHECK_GUEST_FAILURE(run);
		r11 = read_64bit_from_guest_vcpu(vm, run, i,
						 TDX_DATA_REPORT_PORT);

		num_vcpus = r8 & 0xFFFFFFFF;
		max_vcpus = (r8 >> 32) & 0xFFFFFFFF;

		/* first bits 5:0 of rcx represent the GPAW */
		ASSERT_EQ(rcx & 0x3F, max_pa);
		/* next 63:6 bits of rcx is reserved and must be 0 */
		ASSERT_EQ(rcx >> 6, 0);
		ASSERT_EQ(rdx, attributes);
		ASSERT_EQ(num_vcpus, vcpus_ctr);
		ASSERT_EQ(max_vcpus, TDX_GUEST_MAX_NUM_VCPUS);
		/* VCPU_INDEX = i */
		ASSERT_EQ(r9, i);
		/* verify reserved registers are 0 */
		ASSERT_EQ(r10, 0);
		ASSERT_EQ(r11, 0);

		/* Wait for guest to complete execution */
		vcpu_run(vm, i);

		CHECK_GUEST_FAILURE(run);
		CHECK_GUEST_COMPLETION(run);

		printf("\t ... Guest completed run on VCPU=%u\n", i);
	}

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

TDX_GUEST_FUNCTION(guest_shared_mem)
{
	uint64_t gpa_shared_mask;
	uint64_t gva_shared_mask;
	uint64_t shared_gpa;
	uint64_t shared_gva;
	uint64_t gpa_width;
	uint64_t failed_gpa;
	uint64_t ret;
	uint64_t err;

	gva_shared_mask = BIT_ULL(TDX_GUEST_VIRT_SHARED_BIT);
	shared_gpa = 0x80000000;
	shared_gva = gva_shared_mask | shared_gpa;

	/* Read highest order physical bit to calculate shared mask. */
	err = tdcall_vp_info(&gpa_width, 0, 0, 0, 0, 0);
        if (err)
                tdvmcall_fatal(err);

	/* TODO: Remove once shared memory mapping bug is fixed. */
	ret = tdvmcall_map_gpa(shared_gpa, PAGE_SIZE, &failed_gpa);
	if (ret)
		tdvmcall_fatal(ret);

	/* Map gpa as shared. */
	gpa_shared_mask = BIT_ULL(gpa_width - 1);
	ret = tdvmcall_map_gpa(shared_gpa | gpa_shared_mask, PAGE_SIZE,
			       &failed_gpa);
	if (ret)
		tdvmcall_fatal(ret);

	/* Write to shared memory. */
	*(uint16_t *)shared_gva = 0x1234;
	tdvmcall_success();

	/* Read from shared memory; report to host. */
	ret = tdvmcall_io(TDX_TEST_PORT, 2, TDX_IO_WRITE,
			  (uint64_t *)shared_gva);
	if (ret)
		tdvmcall_fatal(ret);

	tdvmcall_success();
}

void verify_shared_mem(void)
{
	struct kvm_vm *vm;
	struct kvm_run *run;
	uint16_t guest_read_val;
	uint64_t shared_gpa;
	uint64_t shared_hva;
	uint64_t shared_pages_num;

	printf("Verifying shared memory\n");

	/* Create a TD VM with no memory. */
	vm = __vm_create(VM_MODE_DEFAULT, 0, O_RDWR, KVM_X86_TDX_VM);

	/* Allocate TD guest memory and initialize the TD. */
	initialize_td(vm);

	/* Initialize the TD vcpu and copy the test code to the guest memory. */
	vm_vcpu_add_tdx(vm, 0);

	/* Allocate shared memory. */
	shared_hva = add_shared_mem_region(vm, 0x80000000, 1);
	TEST_ASSERT(shared_hva != 0,
		    "Guest address not found in guest memory regions\n");

	/* Setup and initialize VM memory. */
	prepare_source_image(vm, guest_shared_mem,
			     TDX_FUNCTION_SIZE(guest_shared_mem), 0);
	finalize_td_memory(vm);

	/* Begin guest execution; guest writes to shared memory. */
	run = vcpu_state(vm, 0);
	printf("\t ... Starting guest execution\n");
	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);

	/* Verify guest write -> host read succeeds. */
	printf("\t ... Guest wrote 0x1234 to shared memory\n");
	if (*(uint16_t *)shared_hva != 0x1234) {
		printf("\t ... FAILED: Host read 0x%x instead of 0x1234\n",
		       *(uint16_t *)shared_hva);
	}
	printf("\t ... Host read 0x%x from shared memory\n",
	       *(uint16_t *)shared_hva);

	/* Verify host write -> guest read succeeds. */
	*((uint16_t *)shared_hva) = 0xABCD;
	printf("\t ... Host wrote 0xabcd to shared memory\n");
	vcpu_run(vm, 0);
	CHECK_GUEST_FAILURE(run);
	CHECK_IO(run, TDX_TEST_PORT, 2, TDX_IO_WRITE);
	guest_read_val = *(uint16_t *)((void *)run + run->io.data_offset);

	if (guest_read_val != 0xABCD) {
		printf("\t ... FAILED: Guest read 0x%x instead of 0xABCD\n",
		       guest_read_val);
		kvm_vm_free(vm);
		return;
	}
	printf("\t ... Guest read 0x%x from shared memory\n",
	       guest_read_val);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

int main(int argc, char **argv)
{
	if (!is_tdx_enabled()) {
		print_skip("TDX is not supported by the KVM");
		exit(KSFT_SKIP);
	}

	run_in_new_process(&verify_td_lifecycle);
	run_in_new_process(&verify_td_ioexit);
	run_in_new_process(&verify_td_cpuid);
	run_in_new_process(&verify_td_cpuid_tdcall);
	run_in_new_process(&verify_td_cpuid_tdcall_invalid_leaf);
	run_in_new_process(&verify_get_td_vmcall_info);
	run_in_new_process(&verify_report_fatal_error);
	run_in_new_process(&verify_guest_writes);
	run_in_new_process(&verify_guest_reads);
	run_in_new_process(&verify_guest_msr_reads);
	run_in_new_process(&verify_guest_msr_writes);
	run_in_new_process(&verify_guest_hlt);
	run_in_new_process(&verify_mmio_reads);
	run_in_new_process(&verify_mmio_writes);
	run_in_new_process(&verify_tdcall_vp_info);
	run_in_new_process(&verify_shared_mem);

	return 0;
}
