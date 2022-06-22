// SPDX-License-Identifier: GPL-2.0-only
#include <linux/proc_fs.h>
#include <linux/sched/mm.h>
#include <linux/seq_file.h>
#include <uapi/asm/prctl.h>
#include <asm/mmu_context.h>

/*
 * Report the amount of time elapsed in millisecond since last AVX512
 * use in the task.
 */
static void avx512_status(struct seq_file *m, struct task_struct *task)
{
	unsigned long timestamp = READ_ONCE(task->thread.fpu.avx512_timestamp);
	long delta;

	if (!timestamp) {
		/*
		 * Report -1 if no AVX512 usage
		 */
		delta = -1;
	} else {
		delta = (long)(jiffies - timestamp);
		/*
		 * Cap to LONG_MAX if time difference > LONG_MAX
		 */
		if (delta < 0)
			delta = LONG_MAX;
		delta = jiffies_to_msecs(delta);
	}

	seq_put_decimal_ll(m, "AVX512_elapsed_ms:\t", delta);
	seq_putc(m, '\n');
}

/*
 * Report architecture specific information
 */
int proc_pid_arch_status(struct seq_file *m, struct pid_namespace *ns,
			struct pid *pid, struct task_struct *task)
{
	struct mm_struct *mm;
	unsigned long untag_mask = -1UL;

	/*
	 * Report AVX512 state if the processor and build option supported.
	 */
	if (cpu_feature_enabled(X86_FEATURE_AVX512F))
		avx512_status(m, task);

	mm = get_task_mm(task);
	if (mm) {
		untag_mask = mm_untag_mask(task->mm);
		mmput(mm);
	}

	seq_printf(m, "untag_mask:\t%#lx\n", untag_mask);

	return 0;
}
