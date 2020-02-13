/* kfence is a temporary name, ideas welcome. */

#include <linux/mm.h>  // required by slub_def.h, should be included there.
#include <linux/set_memory.h>
#include <linux/slab.h>
#include <linux/slub_def.h>
#include <linux/spinlock_types.h>
#include <linux/timer.h>


static void kfence_heartbeat(struct timer_list *timer);
static DEFINE_TIMER(kfence_timer, kfence_heartbeat);

struct list_head kfence_freelist;

struct kfence_freelist_t {
	struct list_head list;
	void *obj;
};

#define KFENCE_NUM_OBJ_LOG 8
#define KFENCE_NUM_OBJ (1 << KFENCE_NUM_OBJ_LOG)

#define KFENCE_SAMPLING_MS 456

void allocate_comb(void)
{
	struct page *pages;
	kfence_freelist_t *objects;
	char *addr;
	int i;

	pages = alloc_pages(GFP_KERNEL, KFENCE_NUM_OBJ_LOG + 1);
	objects = (void **)kmalloc_array(KFENCE_NUM_OBJ, sizeof(kfence_freelist_t), GFP_KERNEL);
	kfence_freelist.next = objects;
	for (i = 0; i < KFENCE_NUM_OBJ) {
		if (i < KFENCE_NUM_OBJ - 1)
			objects[i].next = objects[i + 1];
		else	
	}
}

DEFINE_PER_CPU(void *, stored_freelist);
DEFINE_PER_CPU(struct kmem_cache *, stored_cache);
struct kmem_cache fake_slab_cache;
EXPORT_SYMBOL(fake_slab_cache);

static DEFINE_SPINLOCK(kfence_lock);

void *guarded_alloc(size_t size)
{
	void *res, *guard;
	struct page *page;

	BUG_ON(size > PAGE_SIZE);
	page = alloc_pages(GFP_KERNEL, 1);
	__SetPageSlab(page);
	page->slab_cache = &fake_slab_cache;
	res = (void *)((char*)page_address(page) + PAGE_SIZE - size);
	return res;
}

void guarded_free(void *addr)
{
	void *aligned_addr = ALIGN_DOWN((unsigned long)addr, PAGE_SIZE);
	struct page *page = virt_to_page(aligned_addr);

	__ClearPageSlab(page);
	page->slab_cache = NULL;
	free_pages(aligned_addr, 1);
}

void *kfence_alloc_and_fix_freelist(struct kmem_cache *s)
{
	unsigned long flags;
	struct kmem_cache_cpu *c = raw_cpu_ptr(s->cpu_slab);
	struct kmem_cache *stored = this_cpu_read(stored_cache);
	void *ret = NULL;
	struct page *page;

	if (stored && (s == stored)) {
		spin_lock_irqsave(&kfence_lock, flags);
		stored = this_cpu_read(stored_cache);
		if (stored && (s == stored)) {
			pr_info("stored: %px (%s), s: %px (%s)\n", stored, stored->name, s, s->name);
			ret = guarded_alloc(s->size);
			c->freelist = this_cpu_read(stored_freelist);
			this_cpu_write(stored_freelist, NULL);
			this_cpu_write(stored_cache, NULL);
			page = virt_to_page(ret);
			pr_info("returning %px, slab '%s'\n", ret, page->slab_cache->name);
		} else {
			pr_info("returning NULL\n");
		}
		spin_unlock_irqrestore(&kfence_lock, flags);
		return ret;
	}
	return NULL;
}

bool kfence_free(struct kmem_cache *s, struct page *page,
		 void *head, void *tail, int cnt,
		 unsigned long addr)
{
	void *aligned_head = ALIGN_DOWN((unsigned long)head, PAGE_SIZE);

	if (s != &fake_slab_cache)
		return false;
	BUG_ON(head != tail);
	pr_info("kfence_free(%px)\n", head);
	BUG_ON(aligned_head != page_address(page));
	guarded_free(head);
	return true;
}

size_t kfence_ksize(void *object)
{
	char *upper = ALIGN((unsigned long)object, PAGE_SIZE);
	return upper - (char *)object;
}

static void steal_freelist_locked(void)
{
	struct kmem_cache_cpu *c;
	struct kmem_cache *cache;
	//unsigned long int index = (jiffies / 13) % (KMALLOC_SHIFT_HIGH + 1 - KMALLOC_SHIFT_LOW) + KMALLOC_SHIFT_LOW;
	unsigned long int index = (jiffies / 13) % (KMALLOC_SHIFT_HIGH - 2 - KMALLOC_SHIFT_LOW) + KMALLOC_SHIFT_LOW;

	cache = kmalloc_caches[0][index];
	if (!cache) {
		pr_info("kmalloc_caches[0][%ld] is NULL!\n", index);
		BUG_ON(!cache);
	}
	c = raw_cpu_ptr(cache->cpu_slab);
	BUG_ON(!c);
	this_cpu_write(stored_freelist, c->freelist);
	this_cpu_write(stored_cache, cache);
	c->freelist = 0;
	pr_info("stole freelist from cache %s on CPU%d!\n", cache->name, smp_processor_id());
}

static void kfence_heartbeat(struct timer_list *timer)
{
	unsigned long flags;
	unsigned long delay = msecs_to_jiffies(KFENCE_SAMPLING_MS);

	if (!this_cpu_read(stored_freelist)) {
		spin_lock_irqsave(&kfence_lock, flags);
		if (!this_cpu_read(stored_freelist))
			steal_freelist_locked();
		spin_unlock_irqrestore(&kfence_lock, flags);
	}
	mod_timer(timer, jiffies + delay);
}

int alloc_kmem_cache_cpus(struct kmem_cache *s);
void __init kfence_init(void)
{
	memset(&fake_slab_cache, 0, sizeof(struct kmem_cache));
	fake_slab_cache.name = "fake_slab_cache";
	alloc_kmem_cache_cpus(&fake_slab_cache);
	fake_slab_cache.flags = SLAB_KFENCE;
	mod_timer(&kfence_timer, jiffies + msecs_to_jiffies(KFENCE_SAMPLING_MS));
	pr_info("kfence_init done\n");
}
EXPORT_SYMBOL(kfence_init);
