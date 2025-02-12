/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KCOV_STATE_H
#define _LINUX_KCOV_STATE_H

#ifdef CONFIG_KCOV
struct kcov_state {
	/* See kernel/kcov.c for more details. */
	/*
	 * Coverage collection mode enabled for this task (0 if disabled).
	 * This field is used for synchronization, so it is kept outside of
	 * the below struct.
	 */
	unsigned int mode;

	struct {
		/* Size of the area (in long's). */
		unsigned int size;
		/*
		 * Pointer to user-provided memory used by kcov. This memory may
		 * contain multiple buffers.
		 */
		void *area;

		/* Size of the trace (in long's). */
		unsigned int trace_size;
		/* Buffer for coverage collection, shared with the userspace. */
		unsigned long *trace;

		/* Size of the bitmap (in bits). */
		unsigned int bitmap_size;
		/*
		 * Bitmap for coverage deduplication, shared with the
		 * userspace.
		 */
		unsigned long *bitmap;

		/*
		 * KCOV sequence number: incremented each time kcov is
		 * reenabled, used by kcov_remote_stop(), see the comment there.
		 */
		int sequence;
	} s;
};
#endif /* CONFIG_KCOV */

#endif /* _LINUX_KCOV_STATE_H */
