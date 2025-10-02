/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"

#include <string.h>

static bool file_backed_swap_in(struct page *page, void *kva);
static bool file_backed_swap_out(struct page *page);
static void file_backed_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
    .swap_in = file_backed_swap_in,
    .swap_out = file_backed_swap_out,
    .destroy = file_backed_destroy,
    .type = VM_FILE,
};

/* The initializer of file vm */
void vm_file_init(void) {}

/* Initialize the file backed page */
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva) {
  // 최소 구현
  /* Set up the handler */
  page->operations = &file_ops;
  struct file_page *fp = &page->file;
  fp->file = NULL;
  fp->ofs = 0;
  fp->read_bytes = 0;
  (void)type;
  (void)kva;
  return true;
}

/* Swap in the page by read contents from the file. */
static bool file_backed_swap_in(struct page *page, void *kva) {
  // 최소 구현
  //   struct file_page *file_page UNUSED = &page->file;
  return true;
}

/* Swap out the page by writeback contents to the file. */
static bool file_backed_swap_out(struct page *page) {
  // 최소 구현
  //   struct file_page *file_page UNUSED = &page->file;
  return false;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void file_backed_destroy(struct page *page) {
  struct file_page *file_page = &page->file;
  struct thread *t = thread_current();
  uint64_t *pml4 = t->pml4;

  if (page->frame != NULL) {
    if (pml4 != NULL && pml4_get_page(pml4, page->va) != NULL)
      pml4_clear_page(pml4, page->va);
    vm_free_frame(page->frame);
    page->frame = NULL;
  }

  if (file_page->file != NULL) {
    file_close(file_page->file);
    file_page->file = NULL;
  }
}

/* Do the mmap */
void *do_mmap(void *addr, size_t length, int writable, struct file *file, off_t offset) {}

/* Do the munmap */
void do_munmap(void *addr) {}
