// SPDX-License-Identifier: GPL-2.0
#include "asm-generic/errno-base.h"
#include "linux/printk.h"
#include <linux/cpu.h>
#include <linux/mmu_context.h>
#include <linux/kvm_host.h>
#include <linux/jump_label.h>
#include <linux/trace_events.h>
#include <linux/mmu_context.h>
#include <linux/pagemap.h>
#include <linux/perf_event.h>
#include <linux/freelist.h>

#include <asm/fpu/xcr.h>
#include <asm/virtext.h>

#include <asm/fpu/xcr.h>

#include "capabilities.h"
#include "tdx_errno.h"
#include "tdx_ops.h"
#include "vmx_ops.h"
#include "x86_ops.h"
#include "common.h"
#include "cpuid.h"
#include "lapic.h"
#include "mmu.h"
#include "tdx.h"
#include "vmx.h"
#include "x86.h"

#include <trace/events/kvm.h>
#include "trace.h"

#undef pr_fmt
#define pr_fmt(fmt) "tdx: " fmt

/*
 * workaround to compile.
 * TODO: once the TDX module initiation code in x86 host is merged, remove this.
 * The function returns struct tdsysinfo_struct from TDX module provides which
 * is the system wide information about the TDX module.
 * Return NULL if the TDX module is not ready for KVM to use for TDX VM guest
 * life cycle.
 */
#if __has_include(<asm/tdx_host.h>)
#include <asm/tdx_host.h>
#else
static inline const struct tdsysinfo_struct *tdx_get_sysinfo(void)
{
	return NULL;
}
#endif

/* KeyID range reserved to TDX by BIOS */
static u32 tdx_keyids_start __read_mostly;
static u32 tdx_nr_keyids __read_mostly;
static u32 tdx_seam_keyid __read_mostly;

static void __init tdx_keyids_init(void)
{
	u32 nr_mktme_ids;

	rdmsr(MSR_IA32_MKTME_KEYID_PART, nr_mktme_ids, tdx_nr_keyids);

	/* KeyID 0 is reserved, i.e. KeyIDs are 1-based. */
	tdx_keyids_start = nr_mktme_ids + 1;
	tdx_seam_keyid = tdx_keyids_start;
}

/* TDX KeyID pool */
static DEFINE_IDA(tdx_keyid_pool);

static int tdx_keyid_alloc(void)
{
	if (WARN_ON_ONCE(!tdx_keyids_start || !tdx_nr_keyids))
		return -EINVAL;

	/* The first keyID is reserved for the global key. */
	return ida_alloc_range(&tdx_keyid_pool, tdx_keyids_start + 1,
			       tdx_keyids_start + tdx_nr_keyids - 1,
			       GFP_KERNEL);
}

static void tdx_keyid_free(int keyid)
{
	if (!keyid || keyid < 0)
		return;

	ida_free(&tdx_keyid_pool, keyid);
}

/* Capabilities of KVM + the TDX module. */
struct tdx_capabilities tdx_caps;

static DEFINE_MUTEX(tdx_lock);
static struct mutex *tdx_mng_key_config_lock;

/*
 * A per-CPU list of TD vCPUs associated with a given CPU.  Used when a CPU
 * is brought down to invoke TDH_VP_FLUSH on the approapriate TD vCPUS.
 * Protected by interrupt mask.  This list is manipulated in process context
 * of vcpu and IPI callback.  See tdx_flush_vp_on_cpu().
 */
static DEFINE_PER_CPU(struct list_head, associated_tdvcpus);

static u64 hkid_mask __ro_after_init;
static u8 hkid_start_pos __ro_after_init;

static __always_inline hpa_t set_hkid_to_hpa(hpa_t pa, u16 hkid)
{
	pa &= ~hkid_mask;
	pa |= (u64)hkid << hkid_start_pos;

	return pa;
}

static __always_inline unsigned long tdexit_exit_qual(struct kvm_vcpu *vcpu)
{
	return kvm_rcx_read(vcpu);
}

static __always_inline unsigned long tdexit_ext_exit_qual(struct kvm_vcpu *vcpu)
{
	return kvm_rdx_read(vcpu);
}

static __always_inline unsigned long tdexit_gpa(struct kvm_vcpu *vcpu)
{
	return kvm_r8_read(vcpu);
}

static __always_inline unsigned long tdexit_intr_info(struct kvm_vcpu *vcpu)
{
	return kvm_r9_read(vcpu);
}

#define BUILD_TDVMCALL_ACCESSORS(param, gpr)					\
static __always_inline								\
unsigned long tdvmcall_##param##_read(struct kvm_vcpu *vcpu)			\
{										\
	return kvm_##gpr##_read(vcpu);						\
}										\
static __always_inline void tdvmcall_##param##_write(struct kvm_vcpu *vcpu,	\
						     unsigned long val)		\
{										\
	kvm_##gpr##_write(vcpu, val);						\
}
BUILD_TDVMCALL_ACCESSORS(p1, r12);
BUILD_TDVMCALL_ACCESSORS(p2, r13);
BUILD_TDVMCALL_ACCESSORS(p3, r14);
BUILD_TDVMCALL_ACCESSORS(p4, r15);

static __always_inline unsigned long tdvmcall_exit_type(struct kvm_vcpu *vcpu)
{
	return kvm_r10_read(vcpu);
}
static __always_inline unsigned long tdvmcall_exit_reason(struct kvm_vcpu *vcpu)
{
	return kvm_r11_read(vcpu);
}
static __always_inline void tdvmcall_set_return_code(struct kvm_vcpu *vcpu,
						     long val)
{
	kvm_r10_write(vcpu, val);
}
static __always_inline void tdvmcall_set_return_val(struct kvm_vcpu *vcpu,
						    unsigned long val)
{
	kvm_r11_write(vcpu, val);
}

static inline bool is_td_vcpu_created(struct vcpu_tdx *tdx)
{
	return tdx->tdvpr.added;
}

static inline bool is_td_created(struct kvm_tdx *kvm_tdx)
{
	return kvm_tdx->tdr.added;
}

static inline bool is_hkid_assigned(struct kvm_tdx *kvm_tdx)
{
	return kvm_tdx->hkid >= 0;
}

static inline bool is_td_finalized(struct kvm_tdx *kvm_tdx)
{
	return kvm_tdx->finalized;
}

static inline void tdx_disassociate_vp(struct kvm_vcpu *vcpu)
{
	list_del(&to_tdx(vcpu)->cpu_list);

	/*
	 * Ensure tdx->cpu_list is updated is before setting vcpu->cpu to -1,
	 * otherwise, a different CPU can see vcpu->cpu = -1 and add the vCPU
	 * to its list before its deleted from this CPUs list.
	 */
	smp_wmb();

	vcpu->cpu = -1;
}

void tdx_hardware_enable(void)
{
	INIT_LIST_HEAD(&per_cpu(associated_tdvcpus, raw_smp_processor_id()));
}

void tdx_hardware_disable(void)
{
	int cpu = raw_smp_processor_id();
	struct list_head *tdvcpus = &per_cpu(associated_tdvcpus, cpu);
	struct vcpu_tdx *tdx, *tmp;

	/* Safe variant needed as tdx_disassociate_vp() deletes the entry. */
	list_for_each_entry_safe(tdx, tmp, tdvcpus, cpu_list)
		tdx_disassociate_vp(&tdx->vcpu);
}

static void tdx_clear_page(unsigned long page)
{
	const void *zero_page = (const void *) __va(page_to_phys(ZERO_PAGE(0)));
	unsigned long i;

	/* Zeroing the page is only necessary for systems with MKTME-i. */
	if (!static_cpu_has(X86_FEATURE_MOVDIR64B))
		return;

	for (i = 0; i < 4096; i += 64)
		/* MOVDIR64B [rdx], es:rdi */
		asm (".byte 0x66, 0x0f, 0x38, 0xf8, 0x3a"
		     : : "d" (zero_page), "D" (page + i) : "memory");
}

static int __tdx_reclaim_page(unsigned long va, hpa_t pa, bool do_wb, u16 hkid)
{
	struct tdx_ex_ret ex_ret;
	u64 err;

	err = tdh_phymem_page_reclaim(pa, &ex_ret);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_PHYMEM_PAGE_RECLAIM, err, &ex_ret);
		return -EIO;
	}

	if (do_wb) {
		err = tdh_phymem_page_wbinvd(set_hkid_to_hpa(pa, hkid));
		if (WARN_ON_ONCE(err)) {
			pr_tdx_error(TDH_PHYMEM_PAGE_WBINVD, err, NULL);
			return -EIO;
		}
	}

	tdx_clear_page(va);
	return 0;
}

static int tdx_reclaim_page(unsigned long va, hpa_t pa)
{
	return __tdx_reclaim_page(va, pa, false, 0);
}

static int tdx_alloc_td_page(struct tdx_td_page *page)
{
	page->va = __get_free_page(GFP_KERNEL_ACCOUNT);
	if (!page->va)
		return -ENOMEM;

	page->pa = __pa(page->va);
	return 0;
}

static void tdx_add_td_page(struct tdx_td_page *page)
{
	WARN_ON_ONCE(page->added);
	page->added = true;
}

static void tdx_reclaim_td_page(struct tdx_td_page *page)
{
	if (page->added) {
		if (tdx_reclaim_page(page->va, page->pa))
			return;

		page->added = false;
	}
	free_page(page->va);
}

static void tdx_flush_vp(void *arg)
{
	struct kvm_vcpu *vcpu = arg;
	u64 err;

	/* Task migration can race with CPU offlining. */
	if (vcpu->cpu != raw_smp_processor_id())
		return;

	/*
	 * No need to do TDH_VP_FLUSH if the vCPU hasn't been initialized.  The
	 * list tracking still needs to be updated so that it's correct if/when
	 * the vCPU does get initialized.
	 */
	if (is_td_vcpu_created(to_tdx(vcpu))) {
		err = tdh_vp_flush(to_tdx(vcpu)->tdvpr.pa);
		if (unlikely(err && err != TDX_VCPU_NOT_ASSOCIATED)) {
			if (WARN_ON_ONCE(err))
				pr_tdx_error(TDH_VP_FLUSH, err, NULL);
		}
	}

	tdx_disassociate_vp(vcpu);
}

static void tdx_flush_vp_on_cpu(struct kvm_vcpu *vcpu)
{
	if (unlikely(vcpu->cpu == -1))
		return;

	smp_call_function_single(vcpu->cpu, tdx_flush_vp, vcpu, 1);
}

static int tdx_do_tdh_phymem_cache_wb(void *param)
{
	u64 err = 0;

	/*
	 * We can destroy multiple the guest TDs simultaneously.  Prevent
	 * tdh_phymem_cache_wb from returning TDX_BUSY by serialization.
	 */
	mutex_lock(&tdx_lock);
	do {
		err = tdh_phymem_cache_wb(!!err);
	} while (err == TDX_INTERRUPTED_RESUMABLE);
	mutex_unlock(&tdx_lock);

	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_PHYMEM_CACHE_WB, err, NULL);
		return -EIO;
	}

	return 0;
}

void tdx_vm_teardown(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	cpumask_var_t packages;
	struct kvm_vcpu *vcpu;
	u64 err;
	int ret;
	int i;

	if (!is_hkid_assigned(kvm_tdx))
		return;

	if (!is_td_created(kvm_tdx))
		goto free_hkid;

	mutex_lock(&tdx_lock);
	err = tdh_mng_key_reclaimid(kvm_tdx->tdr.pa);
	mutex_unlock(&tdx_lock);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_KEY_RECLAIMID, err, NULL);
		return;
	}

	kvm_for_each_vcpu(i, vcpu, (&kvm_tdx->kvm))
		tdx_flush_vp_on_cpu(vcpu);

	mutex_lock(&tdx_lock);
	err = tdh_mng_vpflushdone(kvm_tdx->tdr.pa);
	mutex_unlock(&tdx_lock);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_VPFLUSHDONE, err, NULL);
		return;
	}

	if (!zalloc_cpumask_var(&packages, GFP_KERNEL))
		return;
	ret = 0;
	for_each_online_cpu(i) {
		/* tdh_phymem_cache_wb() is per package operation. */
		if (!cpumask_test_and_set_cpu(topology_physical_package_id(i),
						packages))
			continue;

		ret = smp_call_on_cpu(i, tdx_do_tdh_phymem_cache_wb, NULL, 1);
		if (ret)
			break;
	}
	free_cpumask_var(packages);
	if (unlikely(ret))
		return;

	mutex_lock(&tdx_lock);
	err = tdh_mng_key_freeid(kvm_tdx->tdr.pa);
	mutex_unlock(&tdx_lock);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_KEY_FREEID, err, NULL);
		return;
	}

free_hkid:
	tdx_keyid_free(kvm_tdx->hkid);
	kvm_tdx->hkid = -1;
}

void tdx_vm_free(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	int i;

	/* Can't reclaim or free TD pages if teardown failed. */
	if (is_hkid_assigned(kvm_tdx))
		return;

	for (i = 0; i < tdx_caps.tdcs_nr_pages; i++)
		tdx_reclaim_td_page(&kvm_tdx->tdcs[i]);
	kfree(kvm_tdx->tdcs);

	if (kvm_tdx->tdr.added &&
		__tdx_reclaim_page(kvm_tdx->tdr.va, kvm_tdx->tdr.pa, true,
				tdx_seam_keyid))
		return;

	free_page(kvm_tdx->tdr.va);
}

static int tdx_do_tdh_mng_key_config(void *param)
{
	hpa_t *tdr_p = param;
	int cpu, cur_pkg;
	u64 err;

	cpu = raw_smp_processor_id();
	cur_pkg = topology_physical_package_id(cpu);

	mutex_lock(&tdx_mng_key_config_lock[cur_pkg]);
	do {
		err = tdh_mng_key_config(*tdr_p);
	} while (err == TDX_KEY_GENERATION_FAILED);
	mutex_unlock(&tdx_mng_key_config_lock[cur_pkg]);

	/*
	 * TDH.MNG.KEY.CONFIG is per CPU package operation.  Other CPU on the
	 * same package did it for us.
	 */
	if (err == TDX_KEY_CONFIGURED)
		err = 0;

	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_KEY_CONFIG, err, NULL);
		return -EIO;
	}

	return 0;
}

int tdx_vm_init(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	cpumask_var_t packages;
	int ret, i;
	u64 err;

	/*
	 * To generate EPT violation to inject #VE instead of EPT MISCONFIG,
	 * set RWX=0.
	 */
	kvm_mmu_set_mmio_spte_mask(kvm, 0, VMX_EPT_RWX_MASK, 0);

	/* TODO: Enable 2mb and 1gb large page support. */
	kvm->arch.tdp_max_page_level = PG_LEVEL_4K;

	/* vCPUs can't be created until after KVM_TDX_INIT_VM. */
	kvm->max_vcpus = 0;

	kvm_tdx->hkid = tdx_keyid_alloc();
	if (kvm_tdx->hkid < 0)
		return -EBUSY;
	if (WARN_ON_ONCE(kvm_tdx->hkid >> 16)) {
		ret = -EIO;
		goto free_hkid;
	}

	ret = tdx_alloc_td_page(&kvm_tdx->tdr);
	if (ret)
		goto free_hkid;

	kvm_tdx->tdcs = kcalloc(tdx_caps.tdcs_nr_pages, sizeof(*kvm_tdx->tdcs),
				GFP_KERNEL_ACCOUNT);
	if (!kvm_tdx->tdcs)
		goto free_tdr;
	for (i = 0; i < tdx_caps.tdcs_nr_pages; i++) {
		ret = tdx_alloc_td_page(&kvm_tdx->tdcs[i]);
		if (ret)
			goto free_tdcs;
	}

	ret = -EIO;
	mutex_lock(&tdx_lock);
	err = tdh_mng_create(kvm_tdx->tdr.pa, kvm_tdx->hkid);
	mutex_unlock(&tdx_lock);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_CREATE, err, NULL);
		goto free_tdcs;
	}
	tdx_add_td_page(&kvm_tdx->tdr);

	if (!zalloc_cpumask_var(&packages, GFP_KERNEL)) {
		ret = -ENOMEM;
		goto free_tdcs;
	}
	/*
	 * TODO: optimize to invoke the callback only once per CPU package
	 * instead of all CPUS because TDH.MNG.KEY.CONFIG is per CPU package
	 * operation.
	 *
	 * Invoke callback one-by-one to avoid contention because
	 * TDH.MNG.KEY.CONFIG competes for TDR lock.
	 */
	for_each_online_cpu(i) {
		int pkg = topology_physical_package_id(i);

		if (cpumask_test_and_set_cpu(pkg, packages))
			continue;
		ret = smp_call_on_cpu(i, tdx_do_tdh_mng_key_config,
				&kvm_tdx->tdr.pa, 1);
		if (ret)
			break;
	}
	free_cpumask_var(packages);
	if (ret)
  		goto teardown;

	for (i = 0; i < tdx_caps.tdcs_nr_pages; i++) {
		err = tdh_mng_addcx(kvm_tdx->tdr.pa, kvm_tdx->tdcs[i].pa);
		if (WARN_ON_ONCE(err)) {
			pr_tdx_error(TDH_MNG_ADDCX, err, NULL);
			goto teardown;
		}
		tdx_add_td_page(&kvm_tdx->tdcs[i]);
	}

	spin_lock_init(&kvm_tdx->seamcall_lock);

	/*
	 * Note, TDH_MNG_INIT cannot be invoked here.  TDH_MNG_INIT requires a dedicated
	 * ioctl() to define the configure CPUID values for the TD.
	 */
	return 0;

	/*
	 * The sequence for freeing resources from a partially initialized TD
	 * varies based on where in the initialization flow failure occurred.
	 * Simply use the full teardown and destroy, which naturally play nice
	 * with partial initialization.
	 */
teardown:
	tdx_vm_teardown(kvm);
	tdx_vm_free(kvm);
	return ret;

free_tdcs:
	/* @i points at the TDCS page that failed allocation. */
	for (--i; i >= 0; i--)
		free_page(kvm_tdx->tdcs[i].va);
	kfree(kvm_tdx->tdcs);
free_tdr:
	free_page(kvm_tdx->tdr.va);
free_hkid:
	tdx_keyid_free(kvm_tdx->hkid);
	kvm_tdx->hkid = -1;
	return ret;
}

int tdx_vcpu_create(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	int ret, i;

	ret = tdx_alloc_td_page(&tdx->tdvpr);
	if (ret)
		return ret;

	tdx->tdvpx = kcalloc(tdx_caps.tdvpx_nr_pages, sizeof(*tdx->tdvpx),
			GFP_KERNEL_ACCOUNT);
	if (!tdx->tdvpx) {
		ret = -ENOMEM;
		goto free_tdvpr;
	}
	for (i = 0; i < tdx_caps.tdvpx_nr_pages; i++) {
		ret = tdx_alloc_td_page(&tdx->tdvpx[i]);
		if (ret)
			goto free_tdvpx;
	}

	vcpu->arch.efer = EFER_SCE | EFER_LME | EFER_LMA | EFER_NX;

	vcpu->arch.switch_db_regs = KVM_DEBUGREG_AUTO_SWITCH;
	vcpu->arch.cr0_guest_owned_bits = -1ul;
	vcpu->arch.cr4_guest_owned_bits = -1ul;

	vcpu->arch.tsc_offset = to_kvm_tdx(vcpu->kvm)->tsc_offset;
	vcpu->arch.l1_tsc_offset = vcpu->arch.tsc_offset;
	vcpu->arch.guest_state_protected =
		!(to_kvm_tdx(vcpu->kvm)->attributes & TDX_TD_ATTRIBUTE_DEBUG);

	tdx->pi_desc.nv = POSTED_INTR_VECTOR;
	tdx->pi_desc.sn = 1;

	tdx->host_state_need_save = true;
	tdx->host_state_need_restore = false;

	return 0;

free_tdvpx:
	/* @i points at the TDVPX page that failed allocation. */
	for (--i; i >= 0; i--)
		free_page(tdx->tdvpx[i].va);
	kfree(tdx->tdvpx);
free_tdvpr:
	free_page(tdx->tdvpr.va);

	return ret;
}

void tdx_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	vmx_vcpu_pi_load(vcpu, cpu);
	if (vcpu->cpu == cpu)
		return;

	tdx_flush_vp_on_cpu(vcpu);

	local_irq_disable();
	/*
	 * Pairs with the smp_wmb() in tdx_disassociate_vp() to ensure
	 * vcpu->cpu is read before tdx->cpu_list.
	 */
	smp_rmb();

	list_add(&tdx->cpu_list, &per_cpu(associated_tdvcpus, cpu));
	local_irq_enable();
}

void tdx_prepare_switch_to_guest(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	if (!tdx->host_state_need_save)
		return;

	if (likely(is_64bit_mm(current->mm)))
		tdx->msr_host_kernel_gs_base = current->thread.gsbase;
	else
		tdx->msr_host_kernel_gs_base = read_msr(MSR_KERNEL_GS_BASE);

	tdx->host_state_need_save = false;
}

static void tdx_prepare_switch_to_host(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	tdx->host_state_need_save = true;
	if (!tdx->host_state_need_restore)
		return;

	wrmsrl(MSR_KERNEL_GS_BASE, tdx->msr_host_kernel_gs_base);
	tdx->host_state_need_restore = false;
}

void tdx_vcpu_put(struct kvm_vcpu *vcpu)
{
	vmx_vcpu_pi_put(vcpu);
	tdx_prepare_switch_to_host(vcpu);
}

void tdx_vcpu_free(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	int i;

	/* Can't reclaim or free pages if teardown failed. */
	if (is_hkid_assigned(to_kvm_tdx(vcpu->kvm)))
		return;

	for (i = 0; i < tdx_caps.tdvpx_nr_pages; i++)
		tdx_reclaim_td_page(&tdx->tdvpx[i]);
	kfree(tdx->tdvpx);
	tdx_reclaim_td_page(&tdx->tdvpr);

	/*
	 * kvm_free_vcpus()
	 *   -> kvm_unload_vcpu_mmu()
	 *
	 * does vcpu_load() for every vcpu after they already disassociated
	 * from the per cpu list when tdx_vm_teardown(). So we need to
	 * disassociate them again, otherwise the freed vcpu data will be
	 * accessed when do list_{del,add}() on associated_tdvcpus list
	 * later.
	 */
	tdx_flush_vp_on_cpu(vcpu);
	WARN_ON(vcpu->cpu != -1);
}

void tdx_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	struct msr_data apic_base_msr;
	u64 err;
	int i;

	/* TDX doesn't support INIT event. */
	if (WARN_ON(init_event))
		goto td_bugged;
	/* TDX supports only X2APIC enabled. */
	if (WARN_ON(!vcpu->arch.apic))
		goto td_bugged;
	if (WARN_ON(is_td_vcpu_created(tdx)))
		goto td_bugged;

	/*
	 * In TDX case, tsc frequency is per-VM and determined by the parameter
	 * tdh_mng_init().  Forcibly set it instead of max_tsc_khz set by
	 * kvm_arch_vcpu_create().
	 *
	 * This function is called after kvm_arch_vcpu_create() calling
	 * kvm_set_tsc_khz().
	 */
	kvm_set_tsc_khz(vcpu, kvm_tdx->tsc_khz);

	err = tdh_vp_create(kvm_tdx->tdr.pa, tdx->tdvpr.pa);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_VP_CREATE, err, NULL);
		goto td_bugged;
	}
	tdx_add_td_page(&tdx->tdvpr);

	for (i = 0; i < tdx_caps.tdvpx_nr_pages; i++) {
		err = tdh_vp_addcx(tdx->tdvpr.pa, tdx->tdvpx[i].pa);
		if (WARN_ON_ONCE(err)) {
			pr_tdx_error(TDH_VP_ADDCX, err, NULL);
			goto td_bugged;
		}
		tdx_add_td_page(&tdx->tdvpx[i]);
	}

	if (!vcpu->arch.cpuid_entries) {
		/*
		 * On cpu creation, cpuid entry is blank.  Forcibly enable
		 * X2APIC feature to allow X2APIC.
		 */
		struct kvm_cpuid_entry2 *e;

		e = kvmalloc_array(1, sizeof(*e), GFP_KERNEL_ACCOUNT);
		*e  = (struct kvm_cpuid_entry2) {
			.function = 1,	/* Features for X2APIC */
			.index = 0,
			.eax = 0,
			.ebx = 0,
			.ecx = 1ULL << 21,	/* X2APIC */
			.edx = 0,
		};
		vcpu->arch.cpuid_entries = e;
		vcpu->arch.cpuid_nent = 1;
	}
	apic_base_msr.data = APIC_DEFAULT_PHYS_BASE | LAPIC_MODE_X2APIC;
	if (kvm_vcpu_is_reset_bsp(vcpu))
		apic_base_msr.data |= MSR_IA32_APICBASE_BSP;
	apic_base_msr.host_initiated = true;
	if (WARN_ON(kvm_set_apic_base(vcpu, &apic_base_msr)))
		goto td_bugged;

	vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;

	return;

td_bugged:
	vcpu->kvm->vm_bugged = true;
}

static void tdx_complete_interrupts(struct kvm_vcpu *vcpu)
{
	/* Avoid costly SEAMCALL if no nmi was injected */
	if (vcpu->arch.nmi_injected)
		vcpu->arch.nmi_injected = td_management_read8(to_tdx(vcpu),
							      TD_VCPU_PEND_NMI);
}

struct tdx_uret_msr {
	u32 msr;
	unsigned int slot;
	u64 defval;
};

static struct tdx_uret_msr tdx_uret_msrs[] = {
	{.msr = MSR_SYSCALL_MASK,},
	{.msr = MSR_STAR,},
	{.msr = MSR_LSTAR,},
	{.msr = MSR_TSC_AUX,},
};

static void tdx_user_return_update_cache(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(tdx_uret_msrs); i++)
		kvm_user_return_update_cache(tdx_uret_msrs[i].slot,
					     tdx_uret_msrs[i].defval);
}

static void tdx_restore_host_xsave_state(struct kvm_vcpu *vcpu)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);

	if (static_cpu_has(X86_FEATURE_XSAVE) &&
	    host_xcr0 != (kvm_tdx->xfam & supported_xcr0))
		xsetbv(XCR_XFEATURE_ENABLED_MASK, host_xcr0);
	if (static_cpu_has(X86_FEATURE_XSAVES) &&
	    /* PT can be exposed to TD guest regardless of KVM's XSS support */
	    host_xss != (kvm_tdx->xfam & (supported_xss | XFEATURE_MASK_PT)))
		wrmsrl(MSR_IA32_XSS, host_xss);
	if (static_cpu_has(X86_FEATURE_PKU) &&
	    (kvm_tdx->xfam & XFEATURE_MASK_PKRU))
		write_pkru(vcpu->arch.host_pkru);
}

u64 __tdx_vcpu_run(hpa_t tdvpr, void *regs, u32 regs_mask);

static noinstr void tdx_vcpu_enter_exit(struct kvm_vcpu *vcpu,
					struct vcpu_tdx *tdx)
{
	kvm_guest_enter_irqoff();
	tdx->exit_reason.full = __tdx_vcpu_run(tdx->tdvpr.pa, vcpu->arch.regs,
					tdx->tdvmcall.regs_mask);
	kvm_guest_exit_irqoff();
}

fastpath_t tdx_vcpu_run(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	if (unlikely(vcpu->kvm->vm_bugged)) {
		tdx->exit_reason.full = TDX_NON_RECOVERABLE_VCPU;
		return EXIT_FASTPATH_NONE;
	}

	trace_kvm_entry(vcpu);

	if (pi_test_on(&tdx->pi_desc)) {
		apic->send_IPI_self(POSTED_INTR_VECTOR);

		kvm_wait_lapic_expire(vcpu, true);
	}

	tdx_vcpu_enter_exit(vcpu, tdx);

	tdx_user_return_update_cache();
	perf_restore_debug_store();
	tdx_restore_host_xsave_state(vcpu);
	tdx->host_state_need_restore = true;

	vmx_register_cache_reset(vcpu);
	trace_kvm_exit(vcpu, KVM_ISA_VMX);

	tdx_complete_interrupts(vcpu);

	if (tdx->exit_reason.error || tdx->exit_reason.non_recoverable)
		return EXIT_FASTPATH_NONE;

	if (tdx->exit_reason.basic == EXIT_REASON_TDCALL)
		tdx->tdvmcall.rcx = vcpu->arch.regs[VCPU_REGS_RCX];
	else
		tdx->tdvmcall.rcx = 0;
	return EXIT_FASTPATH_NONE;
}

void tdx_inject_nmi(struct kvm_vcpu *vcpu)
{
	td_management_write8(to_tdx(vcpu), TD_VCPU_PEND_NMI, 1);
}

void tdx_handle_exit_irqoff(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	u16 exit_reason = tdx->exit_reason.basic;

	if (exit_reason == EXIT_REASON_EXCEPTION_NMI)
		vmx_handle_exception_nmi_irqoff(vcpu, tdexit_intr_info(vcpu));
	else if (exit_reason == EXIT_REASON_EXTERNAL_INTERRUPT)
		vmx_handle_external_interrupt_irqoff(vcpu,
						     tdexit_intr_info(vcpu));
}

static int tdx_handle_exception(struct kvm_vcpu *vcpu)
{
	u32 intr_info = tdexit_intr_info(vcpu);

	if (is_nmi(intr_info) || is_machine_check(intr_info))
		return 1;

	kvm_pr_unimpl("unexpected exception 0x%x\n", intr_info);
	return -EFAULT;
}

static int tdx_handle_external_interrupt(struct kvm_vcpu *vcpu)
{
	++vcpu->stat.irq_exits;
	return 1;
}

static int tdx_handle_triple_fault(struct kvm_vcpu *vcpu)
{
	vcpu->run->exit_reason = KVM_EXIT_SHUTDOWN;
	vcpu->mmio_needed = 0;
	return 0;
}

static int tdx_emulate_vmcall(struct kvm_vcpu *vcpu)
{
	unsigned long nr, a0, a1, a2, a3, ret;

	/*
	 * ABI for KVM tdvmcall argument:
	 * In Guest-Hypervisor Communication Interface(GHCI) specification,
	 * Non-zero leaf number (R10 != 0) is defined to indicate
	 * vendor-specific.  KVM uses this for KVM hypercall.  NOTE: KVM
	 * hypercall number starts from one.  Zero isn't used for KVM hypercall
	 * number.
	 *
	 * R10: KVM h ypercall number
	 * arguments: R11, R12, R13, R14.
	 */
	nr = kvm_r10_read(vcpu);
	a0 = kvm_r11_read(vcpu);
	a1 = kvm_r12_read(vcpu);
	a2 = kvm_r13_read(vcpu);
	a3 = kvm_r14_read(vcpu);

	ret = __kvm_emulate_hypercall(vcpu, nr, a0, a1, a2, a3, true);

	tdvmcall_set_return_code(vcpu, ret);

	return 1;
}

static int tdx_emulate_cpuid(struct kvm_vcpu *vcpu)
{
	u32 eax, ebx, ecx, edx;

	/* EAX and ECX for cpuid is stored in R12 and R13. */
	eax = tdvmcall_p1_read(vcpu);
	ecx = tdvmcall_p2_read(vcpu);

	kvm_cpuid(vcpu, &eax, &ebx, &ecx, &edx, true);

	/*
	 * The returned value for CPUID (EAX, EBX, ECX, and EDX) is stored into
	 * R12, R13, R14, and R15.
	 */
	tdvmcall_p1_write(vcpu, eax);
	tdvmcall_p2_write(vcpu, ebx);
	tdvmcall_p3_write(vcpu, ecx);
	tdvmcall_p4_write(vcpu, edx);

	tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);

	return 1;
}

static int tdx_emulate_hlt(struct kvm_vcpu *vcpu)
{
	bool interrupt_disabled = tdvmcall_p1_read(vcpu);
	union tdx_vcpu_state_details details;

	tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);

	if (!interrupt_disabled) {
		/*
		 * Virtual interrupt can arrive after TDG.VM.VMCALL<HLT> during
		 * the TDX module executing.  On the other hand, KVM doesn't
		 * know if vcpu was executing in the guest TD or the TDX module.
		 *
		 * CPU mode transition:
		 * TDG.VP.VMCALL<HLT> (SEAM VMX non-root mode) ->
		 * the TDX module (SEAM VMX root mode) ->
		 * KVM (Legacy VMX root mode)
		 *
		 * If virtual interrupt arrives to this vcpu
		 * - In the guest TD executing:
		 *   KVM can handle it in the same way to the VMX case.
		 * - During the TDX module executing:
		 *   The TDX modules switches to KVM with TDG.VM.VMCALL<HLT>
		 *   exit reason.  KVM thinks the guest was running.  So KVM
		 *   vcpu wake up logic doesn't kick in.  Check if virtual
		 *   interrupt is pending and resume vcpu without blocking vcpu.
		 * - KVM executing:
		 *   The existing logic wakes up the target vcpu on injecting
		 *   virtual interrupt in the same way to the VMX case.
		 *
		 * Check if the interrupt is already pending.  If yes, resume
		 * vcpu from guest HLT without emulating hlt instruction.
		 */
		details.full = td_state_non_arch_read64(
			to_tdx(vcpu), TD_VCPU_STATE_DETAILS_NON_ARCH);
		if (details.vmxip)
			return 1;
	}

	return kvm_vcpu_halt(vcpu);
}

static int tdx_complete_pio_in(struct kvm_vcpu *vcpu)
{
	struct x86_emulate_ctxt *ctxt = vcpu->arch.emulate_ctxt;
	unsigned long val = 0;
	int ret;

	WARN_ON(vcpu->arch.pio.count != 1);

	ret = ctxt->ops->pio_in_emulated(ctxt, vcpu->arch.pio.size,
					 vcpu->arch.pio.port, &val, 1);
	WARN_ON(!ret);

	tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);
	tdvmcall_set_return_val(vcpu, val);

	return 1;
}

static int tdx_emulate_io(struct kvm_vcpu *vcpu)
{
	struct x86_emulate_ctxt *ctxt = vcpu->arch.emulate_ctxt;
	unsigned long val = 0;
	unsigned int port;
	int size, ret;

	++vcpu->stat.io_exits;

	size = tdvmcall_p1_read(vcpu);
	port = tdvmcall_p3_read(vcpu);

	if (size != 1 && size != 2 && size != 4) {
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
		return 1;
	}

	if (!tdvmcall_p2_read(vcpu)) {
		ret = ctxt->ops->pio_in_emulated(ctxt, size, port, &val, 1);
		if (!ret)
			vcpu->arch.complete_userspace_io = tdx_complete_pio_in;
		else
			tdvmcall_set_return_val(vcpu, val);
	} else {
		val = tdvmcall_p4_read(vcpu);
		ret = ctxt->ops->pio_out_emulated(ctxt, size, port, &val, 1);

		/* No need for a complete_userspace_io callback. */
		vcpu->arch.pio.count = 0;
	}
	if (ret)
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);
	return ret;
}

static int tdx_complete_mmio(struct kvm_vcpu *vcpu)
{
	unsigned long val = 0;
	gpa_t gpa;
	int size;

	WARN_ON(vcpu->mmio_needed != 1);
	vcpu->mmio_needed = 0;

	if (!vcpu->mmio_is_write) {
		gpa = vcpu->mmio_fragments[0].gpa;
		size = vcpu->mmio_fragments[0].len;

		memcpy(&val, vcpu->run->mmio.data, size);
		tdvmcall_set_return_val(vcpu, val);
		trace_kvm_mmio(KVM_TRACE_MMIO_READ, size, gpa, &val);
	}
	return 1;
}

static inline int tdx_mmio_write(struct kvm_vcpu *vcpu, gpa_t gpa, int size,
				 unsigned long val)
{
	if (kvm_iodevice_write(vcpu, &vcpu->arch.apic->dev, gpa, size, &val) &&
	    kvm_io_bus_write(vcpu, KVM_MMIO_BUS, gpa, size, &val))
		return -EOPNOTSUPP;

	trace_kvm_mmio(KVM_TRACE_MMIO_WRITE, size, gpa, &val);
	return 0;
}

static inline int tdx_mmio_read(struct kvm_vcpu *vcpu, gpa_t gpa, int size)
{
	unsigned long val;

	if (kvm_iodevice_read(vcpu, &vcpu->arch.apic->dev, gpa, size, &val) &&
	    kvm_io_bus_read(vcpu, KVM_MMIO_BUS, gpa, size, &val))
		return -EOPNOTSUPP;

	tdvmcall_set_return_val(vcpu, val);
	trace_kvm_mmio(KVM_TRACE_MMIO_READ, size, gpa, &val);
	return 0;
}

static int tdx_emulate_mmio(struct kvm_vcpu *vcpu)
{
	struct kvm_memory_slot *slot;
	int size, write, r;
	unsigned long val;
	gpa_t gpa;

	WARN_ON(vcpu->mmio_needed);

	size = tdvmcall_p1_read(vcpu);
	write = tdvmcall_p2_read(vcpu);
	gpa = tdvmcall_p3_read(vcpu);
	val = write ? tdvmcall_p4_read(vcpu) : 0;

	if (size != 1 && size != 2 && size != 4 && size != 8)
		goto error;
	if (write != 0 && write != 1)
		goto error;

	/* Strip the shared bit, allow MMIO with and without it set. */
	gpa &= ~(vcpu->kvm->arch.gfn_shared_mask << PAGE_SHIFT);

	if (size > 8u || ((gpa + size - 1) ^ gpa) & PAGE_MASK)
		goto error;

	slot = kvm_vcpu_gfn_to_memslot(vcpu, gpa >> PAGE_SHIFT);
	if (slot && !(slot->flags & KVM_MEMSLOT_INVALID))
		goto error;

	if (!kvm_io_bus_write(vcpu, KVM_FAST_MMIO_BUS, gpa, 0, NULL)) {
		trace_kvm_fast_mmio(gpa);
		return 1;
	}

	if (write)
		r = tdx_mmio_write(vcpu, gpa, size, val);
	else
		r = tdx_mmio_read(vcpu, gpa, size);
	if (!r) {
		/* Kernel completed device emulation. */
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);
		return 1;
	}

	/* Request the device emulation to userspace device model. */
	vcpu->mmio_needed = 1;
	vcpu->mmio_is_write = write;
	vcpu->arch.complete_userspace_io = tdx_complete_mmio;

	vcpu->run->mmio.phys_addr = gpa;
	vcpu->run->mmio.len = size;
	vcpu->run->mmio.is_write = write;
	vcpu->run->exit_reason = KVM_EXIT_MMIO;

	if (write) {
		memcpy(vcpu->run->mmio.data, &val, size);
	} else {
		vcpu->mmio_fragments[0].gpa = gpa;
		vcpu->mmio_fragments[0].len = size;
		trace_kvm_mmio(KVM_TRACE_MMIO_READ_UNSATISFIED, size, gpa, NULL);
	}
	return 0;

error:
	tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);
	return 1;
}

static int tdx_emulate_rdmsr(struct kvm_vcpu *vcpu)
{
	u32 index = tdvmcall_p1_read(vcpu);
	u64 data;

	if (kvm_get_msr(vcpu, index, &data)) {
		trace_kvm_msr_read_ex(index);
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
		return 1;
	}
	trace_kvm_msr_read(index, data);

	tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);
	tdvmcall_set_return_val(vcpu, data);
	return 1;
}

static int tdx_emulate_wrmsr(struct kvm_vcpu *vcpu)
{
	u32 index = tdvmcall_p1_read(vcpu);
	u64 data = tdvmcall_p2_read(vcpu);

	if (kvm_set_msr(vcpu, index, data)) {
		trace_kvm_msr_write_ex(index, data);
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
		return 1;
	}

	trace_kvm_msr_write(index, data);
	tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);
	return 1;
}

static int tdx_report_fatal_error(struct kvm_vcpu *vcpu)
{
	/* Exit to userspace device model for teardown. */
	vcpu->run->exit_reason = KVM_EXIT_SYSTEM_EVENT;
	vcpu->run->system_event.type = KVM_SYSTEM_EVENT_CRASH;
	vcpu->run->system_event.flags = tdvmcall_p1_read(vcpu);
	return 0;
}

static int tdx_map_gpa(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	gpa_t gpa = tdvmcall_p1_read(vcpu);
	gpa_t size = tdvmcall_p2_read(vcpu);
	gpa_t end = gpa + size;

	tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
	if (!IS_ALIGNED(gpa, 4096) || !IS_ALIGNED(size, 4096) ||
		end < gpa ||
		end > kvm->arch.gfn_shared_mask << (PAGE_SHIFT + 1) ||
		kvm_is_private_gpa(kvm, gpa) != kvm_is_private_gpa(kvm, end))
		return 1;

	tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);

#define TDX_MAP_GPA_SIZE_MAX   (16 * 1024 * 1024)
	while (gpa < end) {
		gfn_t s = gpa_to_gfn(gpa);
		gfn_t e = gpa_to_gfn(
			min(roundup(gpa + 1, TDX_MAP_GPA_SIZE_MAX), end));
		int ret = kvm_mmu_map_gpa(vcpu, &s, e);

		if (ret == -EAGAIN)
			e = s;
		else if (ret) {
			tdvmcall_set_return_code(vcpu,
						TDG_VP_VMCALL_INVALID_OPERAND);
			break;
		}

		gpa = gfn_to_gpa(e);

		/*
		 * TODO:
		 * Interrupt this hypercall invocation to return remaining
		 * region to the guest and let the guest to resume the
		 * hypercall.
		 *
		 * The TDX Guest-Hypervisor Communication Interface(GHCI)
		 * specification and guest implementation need to be updated.
		 *
		 * if (gpa < end && need_resched()) {
		 *	size = end - gpa;
		 *	kvm_r12_write(vcpu, gpa);
		 *	kvm_r13_write(vcpu, size);
		 *	tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INTERRUPTED_RESUME);
		 *	break;
		 * }
		 */
		if (gpa < end)
			cond_resched();
	}

	return 1;
}

static int handle_tdvmcall(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	if (unlikely(tdx->tdvmcall.xmm_mask))
		goto unsupported;

	if (tdvmcall_exit_type(vcpu))
		return tdx_emulate_vmcall(vcpu);

	switch (tdvmcall_exit_reason(vcpu)) {
	case EXIT_REASON_CPUID:
		return tdx_emulate_cpuid(vcpu);
	case EXIT_REASON_HLT:
		return tdx_emulate_hlt(vcpu);
	case EXIT_REASON_IO_INSTRUCTION:
		return tdx_emulate_io(vcpu);
	case EXIT_REASON_EPT_VIOLATION:
		return tdx_emulate_mmio(vcpu);
	case EXIT_REASON_MSR_READ:
		return tdx_emulate_rdmsr(vcpu);
	case EXIT_REASON_MSR_WRITE:
		return tdx_emulate_wrmsr(vcpu);
	case TDG_VP_VMCALL_REPORT_FATAL_ERROR:
		return tdx_report_fatal_error(vcpu);
	case TDG_VP_VMCALL_MAP_GPA:
		return tdx_map_gpa(vcpu);
	default:
		break;
	}

unsupported:
	tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
	return 1;
}

void tdx_load_mmu_pgd(struct kvm_vcpu *vcpu, hpa_t root_hpa, int pgd_level)
{
	td_vmcs_write64(to_tdx(vcpu), SHARED_EPT_POINTER, root_hpa & PAGE_MASK);
}

static void tdx_measure_page(struct kvm_tdx *kvm_tdx, hpa_t gpa)
{
	struct tdx_ex_ret ex_ret;
	u64 err;
	int i;

	for (i = 0; i < PAGE_SIZE; i += TDX_EXTENDMR_CHUNKSIZE) {
		err = tdh_mr_extend(kvm_tdx->tdr.pa, gpa + i, &ex_ret);
		if (KVM_BUG_ON(err, &kvm_tdx->kvm)) {
			pr_tdx_error(TDH_MR_EXTEND, err, &ex_ret);
			break;
		}
	}
}

static void __tdx_sept_set_private_spte(struct kvm *kvm, gfn_t gfn,
					enum pg_level level, kvm_pfn_t pfn)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	hpa_t hpa = pfn << PAGE_SHIFT;
	gpa_t gpa = gfn << PAGE_SHIFT;
	struct tdx_ex_ret ex_ret;
	hpa_t source_pa;
	u64 err;

	if (WARN_ON_ONCE(is_error_noslot_pfn(pfn) || kvm_is_reserved_pfn(pfn)))
		return;

	/* TODO: handle large pages. */
	if (KVM_BUG_ON(level != PG_LEVEL_4K, kvm))
		return;

	/* Pin the page, TDX KVM doesn't yet support page migration. */
	get_page(pfn_to_page(pfn));

	/* Build-time faults are induced and handled via TDH_MEM_PAGE_ADD. */
	if (is_td_finalized(kvm_tdx)) {
		err = tdh_mem_page_aug(kvm_tdx->tdr.pa, gpa, hpa, &ex_ret);
		if (KVM_BUG_ON(err, kvm))
			pr_tdx_error(TDH_MEM_PAGE_AUG, err, &ex_ret);
		return;
	}

	/*
	 * In case of TDP MMU, fault handler can run concurrently.  Note
	 * 'source_pa' is a TD scope variable, meaning if there are multiple
	 * threads reaching here with all needing to access 'source_pa', it
	 * will break.  However fortunately this won't happen, because below
	 * TDH_MEM_PAGE_ADD code path is only used when VM is being created
	 * before it is running, using KVM_TDX_INIT_MEM_REGION ioctl (which
	 * always uses vcpu 0's page table and protected by vcpu->mutex).
	 */
	WARN_ON(kvm_tdx->source_pa == INVALID_PAGE);
	source_pa = kvm_tdx->source_pa & ~KVM_TDX_MEASURE_MEMORY_REGION;

	err = tdh_mem_page_add(kvm_tdx->tdr.pa, gpa, hpa, source_pa, &ex_ret);
	if (KVM_BUG_ON(err, kvm))
		pr_tdx_error(TDH_MEM_PAGE_ADD, err, &ex_ret);
	else if ((kvm_tdx->source_pa & KVM_TDX_MEASURE_MEMORY_REGION))
		tdx_measure_page(kvm_tdx, gpa);

	kvm_tdx->source_pa = INVALID_PAGE;
}

static void tdx_sept_set_private_spte(struct kvm *kvm, gfn_t gfn,
				      enum pg_level level, kvm_pfn_t pfn)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);

	/*
	 * Only TDP MMU needs to use spinlock, however for simplicity,
	 * just always use spinlock for seamcall, regardless whether
	 * legacy MMU or TDP MMU is being used.  For legacy MMU it
	 * should not have noticeable performance impact since taking
	 * spinlock w/o needing to wait should be fast.
	 */
	spin_lock(&kvm_tdx->seamcall_lock);
	__tdx_sept_set_private_spte(kvm, gfn, level, pfn);
	spin_unlock(&kvm_tdx->seamcall_lock);
}

static void tdx_sept_drop_private_spte(
	struct kvm *kvm, gfn_t gfn, enum pg_level level, kvm_pfn_t pfn)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn << PAGE_SHIFT;
	hpa_t hpa = pfn << PAGE_SHIFT;
	hpa_t hpa_with_hkid;
	struct tdx_ex_ret ex_ret;
	u64 err = 0;

	/* TODO: handle large pages. */
	if (KVM_BUG_ON(level != PG_LEVEL_4K, kvm))
		return;

	/* See comment in tdx_sept_set_private_spte() */
	spin_lock(&kvm_tdx->seamcall_lock);
	if (is_hkid_assigned(kvm_tdx)) {
		err = tdh_mem_page_remove(kvm_tdx->tdr.pa, gpa, tdx_level, &ex_ret);
		if (KVM_BUG_ON(err, kvm)) {
			pr_tdx_error(TDH_MEM_PAGE_REMOVE, err, &ex_ret);
			goto unlock;
		}

		hpa_with_hkid = set_hkid_to_hpa(hpa, (u16)kvm_tdx->hkid);
		err = tdh_phymem_page_wbinvd(hpa_with_hkid);
		if (WARN_ON_ONCE(err)) {
			pr_tdx_error(TDH_PHYMEM_PAGE_WBINVD, err, NULL);
			goto unlock;
		}
	} else
		err = tdx_reclaim_page((unsigned long)__va(hpa), hpa);

unlock:
	spin_unlock(&kvm_tdx->seamcall_lock);

	if (!err)
		put_page(pfn_to_page(pfn));
}

static int tdx_sept_link_private_sp(struct kvm *kvm, gfn_t gfn,
				    enum pg_level level, void *sept_page)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn << PAGE_SHIFT;
	hpa_t hpa = __pa(sept_page);
	struct tdx_ex_ret ex_ret;
	u64 err;

	/* See comment in tdx_sept_set_private_spte() */
	spin_lock(&kvm_tdx->seamcall_lock);
	err = tdh_mem_sept_add(kvm_tdx->tdr.pa, gpa, tdx_level, hpa, &ex_ret);
	spin_unlock(&kvm_tdx->seamcall_lock);
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MEM_SEPT_ADD, err, &ex_ret);
		return -EIO;
	}

	return 0;
}

static void tdx_sept_zap_private_spte(struct kvm *kvm, gfn_t gfn,
				      enum pg_level level)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn << PAGE_SHIFT;
	struct tdx_ex_ret ex_ret;
	u64 err;

	/* See comment in tdx_sept_set_private_spte() */
	spin_lock(&kvm_tdx->seamcall_lock);
	err = tdh_mem_range_block(kvm_tdx->tdr.pa, gpa, tdx_level, &ex_ret);
	spin_unlock(&kvm_tdx->seamcall_lock);
	if (KVM_BUG_ON(err, kvm))
		pr_tdx_error(TDH_MEM_RANGE_BLOCK, err, &ex_ret);
}

static int tdx_sept_free_private_sp(struct kvm *kvm, gfn_t gfn, enum pg_level level,
				    void *sept_page)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	int ret;

	/*
	 * free_private_sp() is (obviously) called when a shadow page is being
	 * zapped.  KVM doesn't (yet) zap private SPs while the TD is active.
	 */
	if (KVM_BUG_ON(is_hkid_assigned(to_kvm_tdx(kvm)), kvm))
		return -EINVAL;

	/* See comment in tdx_sept_set_private_spte() */
	spin_lock(&kvm_tdx->seamcall_lock);
	ret = tdx_reclaim_page((unsigned long)sept_page, __pa(sept_page));
	spin_unlock(&kvm_tdx->seamcall_lock);

	return ret;
}

static int tdx_sept_tlb_remote_flush(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx;
	u64 err;

	if (!is_td(kvm))
		return -EOPNOTSUPP;

	kvm_tdx = to_kvm_tdx(kvm);
	if (!is_hkid_assigned(kvm_tdx))
		return 0;

	/* If TD isn't finalized, it's before any vcpu running. */
	if (!is_td_finalized(kvm_tdx))
		return 0;

	kvm_tdx->tdh_mem_track = true;

	kvm_make_all_cpus_request(kvm, KVM_REQ_TLB_FLUSH);

	err = tdh_mem_track(kvm_tdx->tdr.pa);
	if (KVM_BUG_ON(err, kvm))
		pr_tdx_error(TDH_MEM_TRACK, err, NULL);

	WRITE_ONCE(kvm_tdx->tdh_mem_track, false);

	return 0;
}

static void tdx_handle_changed_private_spte(
	struct kvm *kvm, gfn_t gfn, enum pg_level level,
	kvm_pfn_t old_pfn, bool was_present, bool was_leaf,
	kvm_pfn_t new_pfn, bool is_present, bool is_leaf, void *sept_page)
{
	WARN_ON(!is_td(kvm));
	lockdep_assert_held(&kvm->mmu_lock);

	if (is_present) {
		/* TDP MMU doesn't change present -> present */
		WARN_ON(was_present);

		/*
		 * Use different call to either set up middle level
		 * private page table, or leaf.
		 */
		if (is_leaf)
			tdx_sept_set_private_spte(kvm, gfn, level, new_pfn);
		else {
			WARN_ON(!sept_page);
			if (tdx_sept_link_private_sp(kvm, gfn, level, sept_page))
				/* failed to update Secure-EPT.  */
				WARN_ON(1);
		}
	} else if (was_leaf) {
		/* non-present -> non-present doesn't make sense. */
		WARN_ON(!was_present);

		/*
		 * Zap private leaf SPTE.  Zapping private table is done
		 * below in handle_removed_tdp_mmu_page().
		 */
		tdx_sept_zap_private_spte(kvm, gfn, level);

		/*
		 * TDX requires TLB tracking before dropping private page.  Do
		 * it here, although it is also done later.
		 * If hkid isn't assigned, the guest is destroying and no vcpu
		 * runs further.  TLB shootdown isn't needed.
		 *
		 * TODO: implement with_range version for optimization.
		 * kvm_flush_remote_tlbs_with_address(kvm, gfn, 1);
		 *   => tdx_sept_tlb_remote_flush_with_range(kvm, gfn,
		 *                                 KVM_PAGES_PER_HPAGE(level));
		 */
		if (is_hkid_assigned(to_kvm_tdx(kvm)))
			kvm_flush_remote_tlbs(kvm);

		tdx_sept_drop_private_spte(kvm, gfn, level, old_pfn);
	}
}

void tdx_apicv_post_state_restore(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	pi_clear_on(&tdx->pi_desc);
	memset(tdx->pi_desc.pir, 0, sizeof(tdx->pi_desc.pir));
}

int tdx_deliver_posted_interrupt(struct kvm_vcpu *vcpu, int vector)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	__vmx_deliver_posted_interrupt(vcpu, &tdx->pi_desc, vector);
	return 0;
}

#define TDX_SEPT_PFERR (PFERR_WRITE_MASK | PFERR_USER_MASK)

static int tdx_handle_ept_violation(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qual;

	if (kvm_is_private_gpa(vcpu->kvm, tdexit_gpa(vcpu)))
		exit_qual = TDX_SEPT_PFERR;
	else {
		exit_qual = tdexit_exit_qual(vcpu);
		if (exit_qual & EPT_VIOLATION_ACC_INSTR) {
			pr_warn("kvm: TDX instr fetch to shared GPA = 0x%lx @ RIP = 0x%lx\n",
				tdexit_gpa(vcpu), kvm_rip_read(vcpu));
			vcpu->run->exit_reason = KVM_EXIT_EXCEPTION;
			vcpu->run->ex.exception = PF_VECTOR;
			vcpu->run->ex.error_code = exit_qual;
			return 0;
		}
	}

	trace_kvm_page_fault(tdexit_gpa(vcpu), exit_qual);
	return __vmx_handle_ept_violation(vcpu, tdexit_gpa(vcpu), exit_qual);
}

static int tdx_handle_ept_misconfig(struct kvm_vcpu *vcpu)
{
	WARN_ON(1);

	vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
	vcpu->run->hw.hardware_exit_reason = EXIT_REASON_EPT_MISCONFIG;

	return 0;
}

int tdx_handle_exit(struct kvm_vcpu *vcpu, fastpath_t fastpath)
{
	union tdx_exit_reason exit_reason = to_tdx(vcpu)->exit_reason;

	if (unlikely(exit_reason.non_recoverable || exit_reason.error)) {
		kvm_pr_unimpl("TD exit 0x%llx, %d\n",
			exit_reason.full, exit_reason.basic);
		if (exit_reason.basic == EXIT_REASON_TRIPLE_FAULT)
			return tdx_handle_triple_fault(vcpu);

		goto unhandled_exit;
	}

	WARN_ON_ONCE(fastpath != EXIT_FASTPATH_NONE);

	switch (exit_reason.basic) {
	case EXIT_REASON_EXCEPTION_NMI:
		return tdx_handle_exception(vcpu);
	case EXIT_REASON_EXTERNAL_INTERRUPT:
		return tdx_handle_external_interrupt(vcpu);
	case EXIT_REASON_TDCALL:
		return handle_tdvmcall(vcpu);
	case EXIT_REASON_EPT_VIOLATION:
		return tdx_handle_ept_violation(vcpu);
	case EXIT_REASON_EPT_MISCONFIG:
		return tdx_handle_ept_misconfig(vcpu);
	case EXIT_REASON_OTHER_SMI:
		/*
		 * If reach here, it's not a MSMI.
		 * #SMI is delivered and handled right after SEAMRET, nothing
		 * needs to be done in KVM.
		 */
		return 1;
	default:
		break;
	}

unhandled_exit:
	vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
	vcpu->run->hw.hardware_exit_reason = exit_reason.full;
	return 0;
}

void tdx_get_exit_info(struct kvm_vcpu *vcpu, u32 *reason,
		u64 *info1, u64 *info2, u32 *intr_info, u32 *error_code)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	*reason = tdx->exit_reason.full;

	*info1 = tdexit_exit_qual(vcpu);
	*info2 = tdexit_ext_exit_qual(vcpu);

	*intr_info = tdexit_intr_info(vcpu);
	*error_code = 0;
}

bool tdx_is_emulated_msr(u32 index, bool write)
{
	switch (index) {
	case MSR_IA32_UCODE_REV:
	case MSR_IA32_ARCH_CAPABILITIES:
	case MSR_IA32_POWER_CTL:
	case MSR_MTRRcap:
	case 0x200 ... 0x26f:
		/* IA32_MTRR_PHYS{BASE, MASK}, IA32_MTRR_FIX*_* */
	case MSR_IA32_CR_PAT:
	case MSR_MTRRdefType:
	case MSR_IA32_TSC_DEADLINE:
	case MSR_IA32_MISC_ENABLE:
	case MSR_KVM_STEAL_TIME:
	case MSR_KVM_POLL_CONTROL:
	case MSR_PLATFORM_INFO:
	case MSR_MISC_FEATURES_ENABLES:
	case MSR_IA32_MCG_CAP:
	case MSR_IA32_MCG_STATUS:
	case MSR_IA32_MCG_CTL:
	case MSR_IA32_MCG_EXT_CTL:
	case MSR_IA32_MC0_CTL ... MSR_IA32_MCx_MISC(28) - 1:
		/* MSR_IA32_MCx_{CTL, STATUS, ADDR, MISC} */
		return true;
	case APIC_BASE_MSR ... APIC_BASE_MSR + 0xff:
		/*
		 * x2APIC registers that are virtualized by the CPU can't be
		 * emulated, KVM doesn't have access to the virtual APIC page.
		 */
		switch (index) {
		case X2APIC_MSR(APIC_TASKPRI):
		case X2APIC_MSR(APIC_PROCPRI):
		case X2APIC_MSR(APIC_EOI):
		case X2APIC_MSR(APIC_ISR) ... X2APIC_MSR(APIC_ISR + APIC_ISR_NR):
		case X2APIC_MSR(APIC_TMR) ... X2APIC_MSR(APIC_TMR + APIC_ISR_NR):
		case X2APIC_MSR(APIC_IRR) ... X2APIC_MSR(APIC_IRR + APIC_ISR_NR):
			return false;
		default:
			return true;
		}
	case MSR_IA32_APICBASE:
	case MSR_EFER:
		return !write;
	case MSR_IA32_MCx_CTL2(0) ... MSR_IA32_MCx_CTL2(31):
		/*
		 * 0x280 - 0x29f: The x86 common code doesn't emulate MCx_CTL2.
		 * Refer to kvm_{get,set}_msr_common(),
		 * kvm_mtrr_{get, set}_msr(), and msr_mtrr_valid().
		 */
	default:
		return false;
	}
}

int tdx_get_msr(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	if (tdx_is_emulated_msr(msr->index, false))
		return kvm_get_msr_common(vcpu, msr);
	return 1;
}

int tdx_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	if (tdx_is_emulated_msr(msr->index, true))
		return kvm_set_msr_common(vcpu, msr);
	return 1;
}

int tdx_smi_allowed(struct kvm_vcpu *vcpu, bool for_injection)
{
	/* SMI isn't supported for TDX. */
	return false;
}

int tdx_enter_smm(struct kvm_vcpu *vcpu, char *smstate)
{
	/* smi_allowed() is always false for TDX as above. */
	WARN_ON_ONCE(1);
	return 0;
}

int tdx_leave_smm(struct kvm_vcpu *vcpu, const char *smstate)
{
	WARN_ON_ONCE(1);
	return 0;
}

void tdx_enable_smi_window(struct kvm_vcpu *vcpu)
{
	/* SMI isn't supported for TDX.  Silently discard SMI request. */
	vcpu->arch.smi_pending = false;
}

void tdx_set_virtual_apic_mode(struct kvm_vcpu *vcpu)
{
	/* Only x2APIC mode is supported for TD. */
	WARN_ON_ONCE(kvm_get_apic_mode(vcpu) != LAPIC_MODE_X2APIC);
}

int tdx_get_cpl(struct kvm_vcpu *vcpu)
{
	return 0;
}

void tdx_cache_reg(struct kvm_vcpu *vcpu, enum kvm_reg reg)
{
	kvm_register_mark_available(vcpu, reg);
	switch (reg) {
	case VCPU_REGS_RSP:
	case VCPU_REGS_RIP:
	case VCPU_EXREG_PDPTR:
	case VCPU_EXREG_CR0:
	case VCPU_EXREG_CR3:
	case VCPU_EXREG_CR4:
		break;
	default:
		KVM_BUG_ON(1, vcpu->kvm);
		break;
	}
}

unsigned long tdx_get_rflags(struct kvm_vcpu *vcpu)
{
	return 0;
}

u64 tdx_get_segment_base(struct kvm_vcpu *vcpu, int seg)
{
	return 0;
}

void tdx_get_segment(struct kvm_vcpu *vcpu, struct kvm_segment *var, int seg)
{
	memset(var, 0, sizeof(*var));
}

int tdx_dev_ioctl(void __user *argp)
{
	struct kvm_tdx_capabilities __user *user_caps;
	struct kvm_tdx_capabilities caps;
	struct kvm_tdx_cmd cmd;

	BUILD_BUG_ON(sizeof(struct kvm_tdx_cpuid_config) !=
		     sizeof(struct tdx_cpuid_config));

	if (copy_from_user(&cmd, argp, sizeof(cmd)))
		return -EFAULT;

	if (cmd.metadata || cmd.id != KVM_TDX_CAPABILITIES)
		return -EINVAL;

	user_caps = (void __user *)cmd.data;
	if (copy_from_user(&caps, user_caps, sizeof(caps)))
		return -EFAULT;

	if (caps.nr_cpuid_configs < tdx_caps.nr_cpuid_configs)
		return -E2BIG;
	caps.nr_cpuid_configs = tdx_caps.nr_cpuid_configs;

	if (copy_to_user(user_caps->cpuid_configs, &tdx_caps.cpuid_configs,
			 tdx_caps.nr_cpuid_configs * sizeof(struct tdx_cpuid_config)))
		return -EFAULT;

	caps.attrs_fixed0 = tdx_caps.attrs_fixed0;
	caps.attrs_fixed1 = tdx_caps.attrs_fixed1;
	caps.xfam_fixed0 = tdx_caps.xfam_fixed0;
	caps.xfam_fixed1 = tdx_caps.xfam_fixed1;

	if (copy_to_user(user_caps, &caps, sizeof(caps)))
		return -EFAULT;

	return 0;
}

static struct kvm_cpuid_entry2 *tdx_find_cpuid_entry(struct kvm_tdx *kvm_tdx,
						u32 function, u32 index)
{
	struct kvm_cpuid_entry2 *e;
	int i;

	for (i = 0; i < kvm_tdx->cpuid_nent; i++) {
		e = &kvm_tdx->cpuid_entries[i];

		if (e->function == function && (e->index == index ||
		    !(e->flags & KVM_CPUID_FLAG_SIGNIFCANT_INDEX)))
			return e;
	}
	return NULL;
}

static int setup_tdparams(struct kvm *kvm, struct td_params *td_params,
			struct kvm_tdx_init_vm *init_vm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct tdx_cpuid_config *config;
	struct kvm_cpuid_entry2 *entry;
	struct tdx_cpuid_value *value;
	u64 guest_supported_xcr0;
	u64 guest_supported_xss;
	u32 guest_tsc_khz;
	int max_pa;
	int i;

	/* init_vm->reserved must be zero */
	if (find_first_bit((unsigned long *)init_vm->reserved,
			   sizeof(init_vm->reserved) * 8) !=
	    sizeof(init_vm->reserved) * 8)
		return -EINVAL;

	td_params->attributes = init_vm->attributes;
	td_params->max_vcpus = init_vm->max_vcpus;

	/* TODO: Enforce consistent CPUID features for all vCPUs. */
	for (i = 0; i < tdx_caps.nr_cpuid_configs; i++) {
		config = &tdx_caps.cpuid_configs[i];

		entry = tdx_find_cpuid_entry(kvm_tdx, config->leaf,
					     config->sub_leaf);
		if (!entry)
			continue;

		/*
		 * Non-configurable bits must be '0', even if they are fixed to
		 * '1' by the TDX module, i.e. mask off non-configurable bits.
		 */
		value = &td_params->cpuid_values[i];
		value->eax = entry->eax & config->eax;
		value->ebx = entry->ebx & config->ebx;
		value->ecx = entry->ecx & config->ecx;
		value->edx = entry->edx & config->edx;
	}

	entry = tdx_find_cpuid_entry(kvm_tdx, 0xd, 0);
	if (entry)
		guest_supported_xcr0 = (entry->eax | ((u64)entry->edx << 32));
	else
		guest_supported_xcr0 = 0;
	guest_supported_xcr0 &= supported_xcr0;

	entry = tdx_find_cpuid_entry(kvm_tdx, 0xd, 1);
	if (entry)
		guest_supported_xss = (entry->ecx | ((u64)entry->edx << 32));
	else
		guest_supported_xss = 0;
	/* PT can be exposed to TD guest regardless of KVM's XSS support */
	guest_supported_xss &= (supported_xss | XFEATURE_MASK_PT);

	max_pa = 36;
	entry = tdx_find_cpuid_entry(kvm_tdx, 0x80000008, 0);
	if (entry)
		max_pa = entry->eax & 0xff;

	td_params->eptp_controls = VMX_EPTP_MT_WB;

	if (cpu_has_vmx_ept_5levels() && max_pa > 48) {
		td_params->eptp_controls |= VMX_EPTP_PWL_5;
		td_params->exec_controls |= TDX_EXEC_CONTROL_MAX_GPAW;
	} else {
		td_params->eptp_controls |= VMX_EPTP_PWL_4;
	}

	if (td_params->attributes & TDX_TD_ATTRIBUTE_PERFMON) {
		pr_warn("TD doesn't support perfmon. KVM needs to save/restore "
			"host perf registers properly.\n");
		return -EOPNOTSUPP;
	}

	/* Setup td_params.xfam */
	td_params->xfam = guest_supported_xcr0 | guest_supported_xss;
	if (td_params->xfam & TDX_TD_XFAM_LBR) {
		pr_warn("TD doesn't support LBR. KVM needs to save/restore "
			"IA32_LBR_DEPTH properly.\n");
		return -EOPNOTSUPP;
	}

	if (td_params->xfam & TDX_TD_XFAM_AMX) {
		pr_warn("TD doesn't support AMX. KVM needs to save/restore "
			"IA32_XFD, IA32_XFD_ERR properly.\n");
		return -EOPNOTSUPP;
	}

	if (init_vm->tsc_khz)
		guest_tsc_khz = init_vm->tsc_khz;
	else
		guest_tsc_khz = max_tsc_khz;
	td_params->tsc_frequency = TDX_TSC_KHZ_TO_25MHZ(guest_tsc_khz);

	BUILD_BUG_ON(sizeof(td_params->mrconfigid) !=
		     sizeof(init_vm->mrconfigid));
	memcpy(td_params->mrconfigid, init_vm->mrconfigid,
	       sizeof(td_params->mrconfigid));
	BUILD_BUG_ON(sizeof(td_params->mrowner) !=
		     sizeof(init_vm->mrowner));
	memcpy(td_params->mrowner, init_vm->mrowner, sizeof(td_params->mrowner));
	BUILD_BUG_ON(sizeof(td_params->mrownerconfig) !=
		     sizeof(init_vm->mrownerconfig));
	memcpy(td_params->mrownerconfig, init_vm->mrownerconfig,
	       sizeof(td_params->mrownerconfig));

	return 0;
}

static int tdx_td_init(struct kvm *kvm, struct kvm_tdx_cmd *cmd)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct kvm_cpuid2 __user *user_cpuid;
	struct kvm_tdx_init_vm init_vm;
	struct td_params *td_params;
	struct tdx_ex_ret ex_ret;
	struct kvm_cpuid2 cpuid;
	int ret;
	u64 err;

	BUILD_BUG_ON(sizeof(init_vm) != 512);

	if (is_td_initialized(kvm))
		return -EINVAL;

	if (cmd->metadata)
		return -EINVAL;

	if (copy_from_user(&init_vm, (void __user *)cmd->data, sizeof(init_vm)))
		return -EFAULT;

	if (init_vm.max_vcpus > KVM_MAX_VCPUS)
		return -EINVAL;

	user_cpuid = (void *)init_vm.cpuid;
	if (copy_from_user(&cpuid, user_cpuid, sizeof(cpuid)))
		return -EFAULT;

	if (cpuid.nent > KVM_MAX_CPUID_ENTRIES)
		return -E2BIG;

	if (copy_from_user(&kvm_tdx->cpuid_entries, user_cpuid->entries,
			   cpuid.nent * sizeof(struct kvm_cpuid_entry2)))
		return -EFAULT;

	BUILD_BUG_ON(sizeof(struct td_params) != 1024);

	td_params = kzalloc(sizeof(struct td_params), GFP_KERNEL_ACCOUNT);
	if (!td_params)
		return -ENOMEM;

	kvm_tdx->cpuid_nent = cpuid.nent;

	ret = setup_tdparams(kvm, td_params, &init_vm);
	if (ret)
		goto free_tdparams;

	err = tdh_mng_init(kvm_tdx->tdr.pa, __pa(td_params), &ex_ret);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_INIT, err, &ex_ret);
		ret = -EIO;
		goto free_tdparams;
	}

	kvm_tdx->tsc_offset = td_tdcs_exec_read64(kvm_tdx, TD_TDCS_EXEC_TSC_OFFSET);
	kvm_tdx->attributes = td_params->attributes;
	kvm_tdx->xfam = td_params->xfam;
	kvm_tdx->tsc_khz = TDX_TSC_25MHZ_TO_KHZ(td_params->tsc_frequency);
	kvm->max_vcpus = td_params->max_vcpus;

	if (td_params->exec_controls & TDX_EXEC_CONTROL_MAX_GPAW)
		kvm->arch.gfn_shared_mask = BIT_ULL(51) >> PAGE_SHIFT;
	else
		kvm->arch.gfn_shared_mask = BIT_ULL(47) >> PAGE_SHIFT;

free_tdparams:
	kfree(td_params);
	if (ret)
		kvm_tdx->cpuid_nent = 0;
	return ret;
}

void tdx_flush_tlb(struct kvm_vcpu *vcpu)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct kvm_mmu *mmu = vcpu->arch.mmu;
	u64 root_hpa = mmu->root_hpa;

	/* Flush the shared EPTP, if it's valid. */
	if (VALID_PAGE(root_hpa))
		ept_sync_context(construct_eptp(vcpu, root_hpa,
						mmu->shadow_root_level));

	while (READ_ONCE(kvm_tdx->tdh_mem_track))
		cpu_relax();
}

static int tdx_init_mem_region(struct kvm *kvm, struct kvm_tdx_cmd *cmd)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct kvm_tdx_init_mem_region region;
	struct kvm_vcpu *vcpu;
	struct page *page;
	kvm_pfn_t pfn;
	int idx, ret = 0;

	/* The BSP vCPU must be created before initializing memory regions. */
	if (!atomic_read(&kvm->online_vcpus))
		return -EINVAL;

	if (cmd->metadata & ~KVM_TDX_MEASURE_MEMORY_REGION)
		return -EINVAL;

	if (copy_from_user(&region, (void __user *)cmd->data, sizeof(region)))
		return -EFAULT;

	/* Sanity check */
	if (!IS_ALIGNED(region.source_addr, PAGE_SIZE))
		return -EINVAL;
	if (!IS_ALIGNED(region.gpa, PAGE_SIZE))
		return -EINVAL;
	if (!region.nr_pages)
		return -EINVAL;
	if (region.gpa + (region.nr_pages << PAGE_SHIFT) <= region.gpa)
		return -EINVAL;
	if (!kvm_is_private_gpa(kvm, region.gpa))
		return -EINVAL;

	vcpu = kvm_get_vcpu(kvm, 0);
	if (mutex_lock_killable(&vcpu->mutex))
		return -EINTR;

	vcpu_load(vcpu);
	idx = srcu_read_lock(&kvm->srcu);

	kvm_mmu_reload(vcpu);

	while (region.nr_pages) {
		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}

		if (need_resched())
			cond_resched();


		/* Pin the source page. */
		ret = get_user_pages_fast(region.source_addr, 1, 0, &page);
		if (ret < 0)
			break;
		if (ret != 1) {
			ret = -ENOMEM;
			break;
		}

		kvm_tdx->source_pa = pfn_to_hpa(page_to_pfn(page)) |
				     (cmd->metadata & KVM_TDX_MEASURE_MEMORY_REGION);

		pfn = kvm_mmu_map_tdp_page(vcpu, region.gpa, TDX_SEPT_PFERR,
					   PG_LEVEL_4K);
		if (is_error_noslot_pfn(pfn) || kvm->vm_bugged)
			ret = -EFAULT;
		else
			ret = 0;

		put_page(page);
		if (ret)
			break;

		region.source_addr += PAGE_SIZE;
		region.gpa += PAGE_SIZE;
		region.nr_pages--;
	}

	srcu_read_unlock(&kvm->srcu, idx);
	vcpu_put(vcpu);

	mutex_unlock(&vcpu->mutex);

	if (copy_to_user((void __user *)cmd->data, &region, sizeof(region)))
		ret = -EFAULT;

	return ret;
}

static int tdx_td_finalizemr(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	u64 err;

	if (!is_td_initialized(kvm) || is_td_finalized(kvm_tdx))
		return -EINVAL;

	err = tdh_mr_finalize(kvm_tdx->tdr.pa);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MR_FINALIZE, err, NULL);
		return -EIO;
	}

	kvm_tdx->finalized = true;
	return 0;
}

int tdx_vm_ioctl(struct kvm *kvm, void __user *argp)
{
	struct kvm_tdx_cmd tdx_cmd;
	int r;

	if (copy_from_user(&tdx_cmd, argp, sizeof(struct kvm_tdx_cmd)))
		return -EFAULT;

	mutex_lock(&kvm->lock);

	switch (tdx_cmd.id) {
	case KVM_TDX_INIT_VM:
		r = tdx_td_init(kvm, &tdx_cmd);
		break;
	case KVM_TDX_INIT_MEM_REGION:
		r = tdx_init_mem_region(kvm, &tdx_cmd);
		break;
	case KVM_TDX_FINALIZE_VM:
		r = tdx_td_finalizemr(kvm);
		break;
	default:
		r = -EINVAL;
		goto out;
	}

	if (copy_to_user(argp, &tdx_cmd, sizeof(struct kvm_tdx_cmd)))
		r = -EFAULT;

out:
	mutex_unlock(&kvm->lock);
	return r;
}

int tdx_vcpu_ioctl(struct kvm_vcpu *vcpu, void __user *argp)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	struct kvm_tdx_cmd cmd;
	u64 err;

	if (tdx->initialized)
		return -EINVAL;

	if (!is_td_initialized(vcpu->kvm) || is_td_finalized(kvm_tdx))
		return -EINVAL;

	if (copy_from_user(&cmd, argp, sizeof(cmd)))
		return -EFAULT;

	if (cmd.metadata || cmd.id != KVM_TDX_INIT_VCPU)
		return -EINVAL;

	err = tdh_vp_init(tdx->tdvpr.pa, cmd.data);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_VP_INIT, err, NULL);
		return -EIO;
	}

	td_vmcs_write16(tdx, POSTED_INTR_NV, POSTED_INTR_VECTOR);
	td_vmcs_write64(tdx, POSTED_INTR_DESC_ADDR, __pa(&tdx->pi_desc));
	td_vmcs_setbit32(tdx, PIN_BASED_VM_EXEC_CONTROL, PIN_BASED_POSTED_INTR);

	tdx->initialized = true;
	return 0;
}

int __init tdx_hardware_setup(struct kvm_x86_ops *x86_ops)
{
	int i, max_pkgs;
	u32 max_pa;
	const struct tdsysinfo_struct *tdsysinfo = tdx_get_sysinfo();

	BUILD_BUG_ON(sizeof(*tdsysinfo) != 1024);
	BUILD_BUG_ON(TDX_MAX_NR_CPUID_CONFIGS != 37);

	if (!enable_ept) {
		pr_warn("Cannot enable TDX with EPT disabled\n");
		return -EINVAL;
	}

	if (tdsysinfo == NULL) {
		WARN_ON_ONCE(cpu_feature_enabled(X86_FEATURE_TDX));
		return -ENODEV;
	}

	if (WARN_ON_ONCE(x86_ops->tlb_remote_flush))
		return -EIO;

	tdx_keyids_init();

	tdx_caps.tdcs_nr_pages = tdsysinfo->tdcs_base_size / PAGE_SIZE;
	tdx_caps.tdvpx_nr_pages = tdsysinfo->tdvps_base_size / PAGE_SIZE - 1;

	tdx_caps.attrs_fixed0 = tdsysinfo->attributes_fixed0;
	tdx_caps.attrs_fixed1 = tdsysinfo->attributes_fixed1;
	tdx_caps.xfam_fixed0 =	tdsysinfo->xfam_fixed0;
	tdx_caps.xfam_fixed1 = tdsysinfo->xfam_fixed1;

	tdx_caps.nr_cpuid_configs = tdsysinfo->num_cpuid_config;
	if (tdx_caps.nr_cpuid_configs > TDX_MAX_NR_CPUID_CONFIGS)
		return -EIO;

	if (!memcpy(tdx_caps.cpuid_configs, tdsysinfo->cpuid_configs,
		    tdsysinfo->num_cpuid_config * sizeof(struct tdx_cpuid_config)))
		return -EIO;

	x86_ops->tlb_remote_flush = tdx_sept_tlb_remote_flush;
	x86_ops->free_private_sp = tdx_sept_free_private_sp;
	x86_ops->handle_changed_private_spte = tdx_handle_changed_private_spte;

	max_pkgs = topology_max_packages();
	tdx_mng_key_config_lock = kcalloc(max_pkgs, sizeof(*tdx_mng_key_config_lock),
				   GFP_KERNEL);
	if (!tdx_mng_key_config_lock)
		return -ENOMEM;
	for (i = 0; i < max_pkgs; i++)
		mutex_init(&tdx_mng_key_config_lock[i]);

	max_pa = cpuid_eax(0x80000008) & 0xff;
	hkid_start_pos = boot_cpu_data.x86_phys_bits;
	hkid_mask = GENMASK_ULL(max_pa - 1, hkid_start_pos);

	for (i = 0; i < ARRAY_SIZE(tdx_uret_msrs); i++) {
		tdx_uret_msrs[i].slot = kvm_find_user_return_msr(tdx_uret_msrs[i].msr);
		if (tdx_uret_msrs[i].slot == -1) {
			/* If any MSR isn't supported, it is a KVM bug */
			pr_err("MSR %x isn't included by kvm_find_user_return_msr\n",
				tdx_uret_msrs[i].msr);
			return -EIO;
		}
	}

	return 0;
}

void __init tdx_pre_kvm_init(unsigned int *vcpu_size,
			unsigned int *vcpu_align, unsigned int *vm_size)
{
	*vcpu_size = sizeof(struct vcpu_tdx);
	*vcpu_align = __alignof__(struct vcpu_tdx);

	if (sizeof(struct kvm_tdx) > *vm_size)
		*vm_size = sizeof(struct kvm_tdx);
}

static __always_inline bool tdx_guest(struct kvm *kvm)
{
	struct kvm_tdx *tdx_kvm = to_kvm_tdx(kvm);

	return tdx_kvm->finalized;
}

static int tdx_lock_two_vms(struct kvm *dst_kvm, struct kvm *src_kvm)
{
	struct kvm_tdx *dst_tdx = to_kvm_tdx(dst_kvm);
	struct kvm_tdx *src_tdx = to_kvm_tdx(src_kvm);

	int r = -EBUSY;

	if (dst_kvm == src_kvm)
		return -EINVAL;

	/*
	 * Bail if these VMs are already involved in a migration to avoid
	 * deadlock between two VMs trying to migrate to/from each other.
	 */
	if (atomic_cmpxchg_acquire(&dst_tdx->migration_in_progress, 0, 1))
		return -EBUSY;

	if (atomic_cmpxchg_acquire(&src_tdx->migration_in_progress, 0, 1))
		goto release_dst;

	r = -EINTR;
	if (mutex_lock_killable(&dst_kvm->lock))
		goto release_src;
	if (mutex_lock_killable_nested(&src_kvm->lock, SINGLE_DEPTH_NESTING))
		goto unlock_dst;
	return 0;

unlock_dst:
	mutex_unlock(&dst_kvm->lock);
release_src:
	atomic_set_release(&src_tdx->migration_in_progress, 0);
release_dst:
	atomic_set_release(&dst_tdx->migration_in_progress, 0);
	return r;
}

static void tdx_unlock_two_vms(struct kvm *dst_kvm, struct kvm *src_kvm)
{
	struct kvm_tdx *dst_tdx = to_kvm_tdx(dst_kvm);
	struct kvm_tdx *src_tdx = to_kvm_tdx(src_kvm);

	mutex_unlock(&dst_kvm->lock);
	mutex_unlock(&src_kvm->lock);
	atomic_set_release(&dst_tdx->migration_in_progress, 0);
	atomic_set_release(&src_tdx->migration_in_progress, 0);
}

static int tdx_lock_vcpus_for_migration(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	unsigned long i, j;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (mutex_lock_killable(&vcpu->mutex))
			goto out_unlock;
	}

	return 0;

out_unlock:
	kvm_for_each_vcpu(j, vcpu, kvm) {
		if (i == j)
			break;

		mutex_unlock(&vcpu->mutex);
	}
	return -EINTR;
}

static void tdx_unlock_vcpus_for_migration(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	unsigned long i;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		mutex_unlock(&vcpu->mutex);
	}
}

static int tdx_migrate_from(struct kvm *dst, struct kvm *src)
{
	struct tdx_td_page empty_td_page = { 0, 0, false };
	struct vcpu_tdx *dst_tdx_vcpu, *src_tdx_vcpu;
	struct kvm_memory_slot *src_slot, *dst_slot;
	struct kvm_memslots *src_slots, *dst_slots;
	struct kvm_vcpu *dst_vcpu, *src_vcpu;
	struct kvm_tdx *src_tdx, *dst_tdx;
	int ret, i, j;

	src_tdx = to_kvm_tdx(src);
	dst_tdx = to_kvm_tdx(dst);

	/* Check memslots consistency */
	/* TODO: Do we also need to check consistency for as_id == SMM? */
	src_slots = __kvm_memslots(src, 0);
	dst_slots = __kvm_memslots(dst, 0);

	ret = -EINVAL;

	if (src_slots->used_slots != dst_slots->used_slots)
		goto abort;

	for (i = 0; i < src_slots->used_slots; i++) {
		src_slot = &src_slots->memslots[i];
		dst_slot = &dst_slots->memslots[i];

		if (src_slot->base_gfn != dst_slot->base_gfn)
			goto abort;

		if (src_slot->npages != dst_slot->npages)
			goto abort;

		if (src_slot->flags != dst_slot->flags)
			goto abort;
	}

	/* TODO: Add checks to make sure attributes, cpuid_entries etc. match
	 * between src and dst VMs.
	 */


	/* Teardown the destination VM.
	 * This call will reclaim hkid.
	 */
	tdx_vm_teardown(dst);

	/* Free each of the destination vCPUs.
	 * This will reclaim all the tdvpr and tdvpx pages.
	 */
	kvm_for_each_vcpu(i, dst_vcpu, dst)
		tdx_vcpu_free(dst_vcpu);

	/* Free the destination VM.
	 * This will reclaim the tdr and tdcs pages.
	 */
	tdx_vm_free(dst);

	/* Copy all the state from src_tdx to dst_tdx */
	dst_tdx->hkid = src_tdx->hkid;
	dst_tdx->tdr = src_tdx->tdr;

	dst_tdx->tdcs = kcalloc(tdx_caps.tdcs_nr_pages, sizeof(*dst_tdx->tdcs),
				GFP_KERNEL_ACCOUNT);
	if (!dst_tdx->tdcs) {
		ret = -ENOMEM;
		goto abort;
	}
	memcpy(dst_tdx->tdcs, src_tdx->tdcs,
	       tdx_caps.tdcs_nr_pages * sizeof(*dst_tdx->tdcs));

	/* All other state such as attributes and cpuid_entries were already
	 * used in tdx_td_init, tdx_vcpu_reset etc.
	 * Changing the values here won't have any effect.
	 */

	/* Flush the vCPUs of the src. This will disassociate the TDX vCPUs from
	 * the LPs and must be called from the LP currently associated with the
	 * vCPU.
	 */
	kvm_for_each_vcpu(i, src_vcpu, src)
		tdx_flush_vp_on_cpu(src_vcpu);

	/* Copy per-vCPU state */
	kvm_for_each_vcpu(i, src_vcpu, src) {
		src_tdx_vcpu = to_tdx(src_vcpu);
		dst_vcpu = kvm_get_vcpu(dst, i);
		dst_tdx_vcpu = to_tdx(dst_vcpu);

		dst_tdx_vcpu->tdvpr = src_tdx_vcpu->tdvpr;

		dst_tdx_vcpu->tdvpx = kcalloc(tdx_caps.tdvpx_nr_pages,
					      sizeof(*dst_tdx_vcpu->tdvpx),
					      GFP_KERNEL_ACCOUNT);
		if (!dst_tdx->tdcs) {
			ret = -ENOMEM;
			goto abort;
		}
		memcpy(dst_tdx_vcpu->tdvpx, src_tdx_vcpu->tdvpx,
		       tdx_caps.tdvpx_nr_pages * sizeof(*dst_tdx_vcpu->tdvpx));

		for (j = 0; j < tdx_caps.tdvpx_nr_pages; j++)
			src_tdx_vcpu->tdvpx[j] = empty_td_page;

		src_tdx_vcpu->tdvpr = empty_td_page;
	}

	/* Copy EPT tables for each vCPU */
	kvm_for_each_vcpu(i, src_vcpu, src) {
		dst_vcpu = kvm_get_vcpu(dst, i);

		if (kvm_mmu_move_private_pages_from(dst_vcpu, src_vcpu)) {
			ret = -EINVAL;
			goto abort;
		}
	}

	WARN_ON(!src_tdx->finalized);
	dst_tdx->finalized = true;

	/* Clear source VM to avoid freeing the hkid and pages on VM put */
	src_tdx->hkid = 0;
	src_tdx->tdr = empty_td_page;
	for (i = 0; i < tdx_caps.tdcs_nr_pages; i++)
		src_tdx->tdcs[i] = empty_td_page;

	return 0;

abort:
	/* TODO: Add more cleanup in case we failed half way through. */
	dst_tdx->hkid = 0;
	dst_tdx->tdr = empty_td_page;

	return ret;
}

int tdx_vm_copy_enc_context_from(struct kvm *kvm, unsigned int source_fd)
{
	struct file *source_kvm_file;
	struct kvm_vcpu *src_vcpu;
	struct kvm *source_kvm;
	int ret, i;

	source_kvm_file = fget(source_fd);
	if (!file_is_kvm(source_kvm_file)) {
		ret = -EBADF;
		goto out_fput;
	}

	source_kvm = source_kvm_file->private_data;
	ret = tdx_lock_two_vms(kvm, source_kvm);
	if (ret)
		goto out_fput;

	if (tdx_guest(kvm) || !tdx_guest(source_kvm)) {
		ret = -EINVAL;
		goto out_unlock;
	}

	if (atomic_read(&kvm->online_vcpus) !=
	    atomic_read(&source_kvm->online_vcpus))
		return -EINVAL;

	kvm_for_each_vcpu(i, src_vcpu, source_kvm) {
		if (!src_vcpu->arch.guest_state_protected)
			return -EINVAL;
	}

	ret = tdx_lock_vcpus_for_migration(kvm);
	if (ret)
		goto out_unlock;
	ret = tdx_lock_vcpus_for_migration(source_kvm);
	if (ret)
		goto out_dst_vcpu;

	ret = tdx_migrate_from(kvm, source_kvm);
	if (ret)
		goto out_source_vcpu;

	kvm_vm_bugged(source_kvm);
	ret = 0;

out_source_vcpu:
	tdx_unlock_vcpus_for_migration(source_kvm);
out_dst_vcpu:
	tdx_unlock_vcpus_for_migration(kvm);
out_unlock:
	tdx_unlock_two_vms(kvm, source_kvm);
out_fput:
	if (source_kvm_file)
		fput(source_kvm_file);
	return ret;
}
