// KFENCE api

#ifdef CONFIG_KFENCE
void kfence_init(void);
void *kfence_alloc_and_fix_freelist(struct kmem_cache *s);
bool kfence_free(struct kmem_cache *s, struct page *page,
		 void *head, void *tail, int cnt,
		 unsigned long addr);
size_t kfence_ksize(void *object);

#else
void kfence_init(void) {}
void *kfence_alloc_and_fix_freelist(struct kmem_cache *s)
{
	return NULL;
}
bool kfence_free(struct kmem_cache *s, struct page *page,
		 void *head, void *tail, int cnt,
		 unsigned long addr)
{
	return false;
}

size_t kfence_ksize(void *object)
{
	return 0;
}
#endif
