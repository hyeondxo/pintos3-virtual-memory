/* vm.c: Generic interface for virtual memory objects. */

#include "vm/vm.h"

#include <stdio.h>
#include <string.h>

#include "kernel/hash.h"
#include "threads/malloc.h"
#include "vm/inspect.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void) {
  vm_anon_init();
  vm_file_init();
#ifdef EFILESYS /* For project 4 */
  pagecache_init();
#endif
  register_inspect_intr();
  /* DO NOT MODIFY UPPER LINES. */
  /* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type page_get_type(struct page *page) {
  int ty = VM_TYPE(page->operations->type);
  switch (ty) {
    case VM_UNINIT:
      return VM_TYPE(page->uninit.type);
    default:
      return ty;
  }
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
//데이터를 만들겠다는 약속을 설정하는 함수, load_segment한테서 aux 구조체를 받고
// uninit_new를 생성한다, 페이지 폴트 전에 설정을 하는 함수 [unint으로 설정된
//상태, 데이터는 아작 안올라감 ]
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
                                    vm_initializer *init, void *aux) {
  struct supplemental_page_table *spt = &thread_current()->spt;

  /* Check wheter the upage is already occupied or not. */
  // upage라는 주소를 가보았더니 아무것도 없다(채워 넣어도 된다)
  if (spt_find_page(spt, upage) == NULL) {
    /* TODO: Create the page, fetch the initialier according to the VM type,
     * TODO: and then create "uninit" page struct by calling uninit_new. You
     * TODO: should modify the field after calling the uninit_new. */
    struct page *page = malloc(sizeof(struct page));
    if (page == NULL) return false;

    enum vm_type base_type = VM_TYPE(type);
    if (base_type == VM_ANON) {
      uninit_new(page, upage, init, type, aux, anon_initializer);
    } else if (base_type == VM_FILE) {
      uninit_new(page, upage, init, type, aux, file_backed_initializer);
    } else {
      free(page);
      return false;
    }
    page->writable = writable;

    /* TODO: Insert the page into the spt. */
    if (!spt_insert_page(spt, page)) {
      free(page);
      return false;
    }

    return true;
  }
  return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *spt_find_page(struct supplemental_page_table *spt, void *va UNUSED) {
  va = pg_round_down(va);
  struct page page;
  page.va = va;

  struct hash_elem *e = hash_find(&spt->h, &page.h_elem);
  if (e != NULL) {
    struct page *page = hash_entry(e, struct page, h_elem);
    return page;
  }

  return NULL;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt, struct page *page) {
  int succ = false;
  /* TODO: Fill this function. */
  if (hash_insert(&spt->h, &page->h_elem) == NULL) {
    succ = true;
  }
  return succ;
}

void spt_remove_page(struct supplemental_page_table *spt UNUSED, struct page *page) {
  hash_delete(&spt->h, &page->h_elem);
  vm_dealloc_page(page);
}

/* Get the struct frame, that will be evicted. */
static struct frame *vm_get_victim(void) {
  struct frame *victim = NULL;
  /* TODO: The policy for eviction is up to you. */

  return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *vm_evict_frame(void) {
  struct frame *victim UNUSED = vm_get_victim();
  /* TODO: swap out the victim and return the evicted frame. */

  return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
/* 새로운 물리 프레임을 얻을 때 사용 */
static struct frame *vm_get_frame(void) {
  struct frame *frame = NULL;
  /* TODO: Fill this function. */

  /* 물리주소 할당
   * PAL_USER 는 메모리 풀(커널/유저) 중 유저풀
   */
  void *kva = palloc_get_page(PAL_USER);
  if (!kva) {
    PANIC("todo:swap-out");
  }
  frame = malloc(sizeof(struct frame));
  if (!frame) {
    PANIC("todo:?");
  }
  /* 프레임 초기화 */
  frame->kva = kva;
  frame->page = NULL;

  ASSERT(frame != NULL);
  ASSERT(frame->page == NULL);
  return frame;
}

void vm_free_frame(struct frame *frame) {
  if (frame == NULL) return;

  // TODO: 프레임 테이블 도입 시 락, 전역 자료구조, 핀 처리 구현

  // 페이지와의 양방향 연결을 끊기
  if (frame->page != NULL) {
    if (frame->page->frame == frame) frame->page->frame = NULL;
    frame->page = NULL;
  }
  // 실제 물리 페이지 반환
  palloc_free_page(frame->kva);
  // 프레임 구조체 해제
  free(frame);
}

/* Growing the stack. */
/**
 * 페이지 폴트가 스택 영역에서 발생했고, 스택 확장 조건을 만족할 때
 * 해당 폴트 주소를 포함하는 한 개 이상의 익명 페이지를 할당,매핑하여 스택을 아래로 확장
 * addr : 폴트가 발생한 가상 주소
 */
static void vm_stack_growth(void *addr) {
  if (addr == NULL || !is_user_vaddr(addr)) return;

  void *page_addr = pg_round_down(addr);  // 페이지 경계
  if (!vm_alloc_page(VM_ANON | VM_MARKER_0, page_addr, true)) return;
  if (!vm_claim_page(page_addr)) {  // 반드시 page_addr 사용
    // 실패 시 등록 회수(선택)
    struct supplemental_page_table *spt = &thread_current()->spt;
    struct page *p = spt_find_page(spt, page_addr);
    if (p) spt_remove_page(spt, p);
    return;
  }
}
/* Handle the fault on write_protected page */
static bool vm_handle_wp(struct page *page) {
  if (page == NULL) return false;

  if (!page->writable) return false;

  return false;
}

/* Return true on success */
/**
 * 페이지 폴트에 대한 전반적인 처리 함수
 * f : 폴트 당시의 CPU 레지스터 상태를 담은 인터럽트 프레임
 * addr : 폴트가 발생한 가상주소
 * user : 폴트가 사용자 모드에서 발생했는지 여부
 * write : 접근이 쓰기였는지 여부
 * not_present : PTE에 주소 매핑 자체가 존재하는지
 * - true : PTE 자체가 없음 -> SPT를 확인하여 해결
 * - false : PTE는 있는데 잘못된 접근임
 * 읽기 전용 페이지에 쓰기 시도, 사용자 모드에서 커널 전용 페이지 접근 등
 */
bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool user, bool write,
                         bool not_present) {
  struct thread *curr = thread_current();
  struct supplemental_page_table *spt = &curr->spt;

  // printf("[DEBUG] vm_try_handle_fault: addr=%p, user=%d, write=%d, not_present=%d\n", addr, user,
  //        write, not_present);

  // 1. 잘못된 주소일 경우
  if (addr == NULL || !is_user_vaddr(addr) || (user && is_kernel_vaddr(addr))) {
    // printf("[DEBUG] return false: invalid addr=%p (NULL/out of range/kernel)\n", addr);
    return false;
  }

  void *fault_page = pg_round_down(addr);
  // printf("[DEBUG] fault_page=%p\n", fault_page);

  // 2. 권한 위반 (P=1인데 write 등)
  if (!not_present) {
    if (write) {
      struct page *p = spt_find_page(spt, fault_page);
      if (p == NULL) {
        // printf("[DEBUG] return false: write fault but page not found at %p\n", fault_page);
        return false;
      }
      // printf("[DEBUG] handling write-protection at %p\n", fault_page);
      return vm_handle_wp(p);
    }
    // printf("[DEBUG] return false: not_present=0 and not write\n");
    return false;
  }

  // 3. 페이지 조회
  struct page *page = spt_find_page(spt, fault_page);
  if (page == NULL) {
    uint8_t *top = (uint8_t *)USER_STACK;
    uint8_t *low = (uint8_t *)(USER_STACK - (1 << 20));  // 1MB 한계
    uint8_t *a = (uint8_t *)addr;
    bool in_range = (a >= low && a < top);

    uint8_t *ursp = user ? (uint8_t *)f->rsp : (uint8_t *)curr->stack_pointer;
    bool near_rsp = (ursp != NULL && a >= ursp - 32 && a < top);

    // printf("[DEBUG] page not found, addr=%p, in_range=%d, near_rsp=%d, ursp=%p\n", addr,
    // in_range,
    //  near_rsp, ursp);

    if (in_range && near_rsp) {
      // printf("[DEBUG] stack growth triggered at fault_page=%p\n", fault_page);
      vm_stack_growth(fault_page);
      page = spt_find_page(spt, fault_page);
      if (page == NULL) {
        // printf("[DEBUG] return false: stack growth failed at %p\n", fault_page);
        return false;
      }
    } else {
      // printf("[DEBUG] return false: not stack growth case (addr=%p)\n", addr);
      return false;
    }
  }

  // printf("[DEBUG] try to claim page=%p\n", page);
  bool result = vm_do_claim_page(page);
  if (!result) {
    // printf("[DEBUG] return false: vm_do_claim_page failed at %p\n", page->va);
  } else {
    // printf("[DEBUG] success: page claimed at %p\n", page->va);
  }
  return result;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page) {
  destroy(page);
  free(page);
}

/* Claim the page that allocate on VA. */
/* 유저가상주소(va)에 대한 페이지를 찾아서 vm_do_claim_page()로 전달 */
bool vm_claim_page(void *va) {
  struct page *page = NULL;
  /* TODO: Fill this function */
  struct supplemental_page_table *spt = &thread_current()->spt;
  page = spt_find_page(spt, va);
  /* 페이지 없는 경우 */
  if (!page) return false;  // 등록된 페이지가 없으면 실패.
  return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
/* 페이지와 프레임을 매핑 */
static bool vm_do_claim_page(struct page *page) {
  struct frame *frame = vm_get_frame();

  if (!frame) return false;

  frame->page = page;
  page->frame = frame;

  /* 먼저 내용 채우기 */
  if (!swap_in(page, frame->kva)) {
    page->frame = NULL;
    frame->page = NULL;
    vm_free_frame(frame);
    return false;
  }

  /* 그 다음 매핑 */
  if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable)) {
    /* 매핑 실패시 프레임 반납 */
    page->frame = NULL;
    frame->page = NULL;
    vm_free_frame(frame);
    return false;
  }
  return true;
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt) {
  struct hash *spt_hash = &spt->h;
  hash_init(spt_hash, page_hash_func, compare_hash_adrr, NULL);
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst,
                                  struct supplemental_page_table *src) {
  if (src == NULL) return;
  if (hash_empty(&src->h)) return;  // 비어있으면 바로 종료

  struct hash_iterator i;
  hash_first(&i, &src->h);  //부모 SPT를 순회

  while (hash_next(&i)) {
    struct page *parent_page = hash_entry(hash_cur(&i), struct page, h_elem);
    enum vm_type type = parent_page->operations->type;
    enum vm_type real_type = page_get_type(parent_page);
    // printf("[!!!] But the value for switch is type = %d\n", real_type);
    // printf("[!!!] But the value for switch is type = %d\n", type);
    void *upage = parent_page->va;
    bool writable = parent_page->writable;
    switch (type) {
      case VM_UNINIT:
        /* UNINIT 페이지: 아직 물리 메모리에 로드되지 않은 페이지
         * 부모의 초기화 정보를 그대로 자식에게 물려줌 */
        struct uninit_page *uninit = &parent_page->uninit;
        if (!vm_alloc_page_with_initializer(real_type, upage, writable, uninit->init, uninit->aux))
          return false;
        break;
      case VM_ANON:
      case VM_FILE:
        /* ANON 또는 FILE 페이지: 이미 물리 메모리에 내용이 로드된 페이지
           독자적인 물리 공간을 가져야 함
        */
        if (!vm_alloc_page_with_initializer(VM_ANON, upage, writable, NULL, NULL)) {
          return false;
        }  // SPT 에 빈공간 할당
        // 2. 빈공간을 자식의 페이지를 SPT에서 다시 찾음
        struct page *child_page = spt_find_page(dst, upage);
        if (child_page == NULL) {
          // supplemental_page_table_kill(dst);
          return false;
        }
        // 3. 자식 페이지에 물리 프레임을 할당, 페이지 테이블에 매핑
        if (!vm_claim_page(child_page->va)) {
          // supplemental_page_table_kill(dst);
          return false;
        }
        // printf("parent_page->frame->kva: %p\n", parent_page->frame->kva);
        // printf("child_page->frame->kva: %p\n", child_page->frame->kva);
        // printf("[DEBUG] child_page->writable = %d\n", child_page->writable);
        memcpy(child_page->frame->kva, parent_page->frame->kva,
               PGSIZE);  //빈공간에 부모 내용 자식에 쓰기 //커널 가상 주소(Kernel Virtual Address)
        break;
    }
  }
  // 모든 페이지 복사가 성공적으로 끝나면 true를 반환
  return true;
}

//보조 페이지 테이블(Supplemental Page Table, SPT)의 자원을 해제
void supplemental_page_table_kill(struct supplemental_page_table *spt) {
  /* TODO: Destroy all the supplemental_page_table hold by thread and
   * TODO: writeback all the modified contents to the storage. */
  if (spt == NULL) return;
  if (hash_empty(&spt->h)) return;  // 비어있으면 바로 종료
  struct list to_free;
  list_init(&to_free);
  struct hash_iterator i;
  hash_first(&i, &spt->h);
  while (hash_next(&i)) {
    struct page *current_page = hash_entry(hash_cur(&i), struct page, h_elem);
    list_push_back(&to_free, &current_page->aux_elem);
  }
  while (!list_empty(&to_free)) {
    struct list_elem *e = list_pop_front(&to_free);
    struct page *page = list_entry(e, struct page, aux_elem);
    // printf("[DEBUG] kill: va=%p, frame=%p, type=%d\n", page->va, page->frame,
    // page_get_type(page));
    destroy(page);
    hash_delete(&spt->h, &page->h_elem);
    free(page);
  }
}
uint64_t page_hash_func(const struct hash_elem *elem, void *aux UNUSED) {
  const struct page *p = hash_entry(elem, struct page, h_elem);

  return hash_bytes(&p->va, sizeof(p->va));
}

bool compare_hash_adrr(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
  struct page *p_a = hash_entry(a, struct page, h_elem);
  struct page *p_b = hash_entry(b, struct page, h_elem);

  return p_a->va < p_b->va;
}
