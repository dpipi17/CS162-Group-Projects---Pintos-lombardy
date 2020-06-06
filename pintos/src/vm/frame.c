#include "lib/kernel/hash.h"
#include <stdio.h>
#include "vm/frame.h"
#include "vm/swap.h"
#include "vm/page.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

static struct lock lock;
static unsigned hash_func(const struct hash_elem *elem, void *aux);
static bool less_func(const struct hash_elem * a, const struct hash_elem * b, void *aux);
struct frame_table_elem* frame_to_evict();

void frame_init(void){
    hash_init(&frame_table, hash_func, less_func, NULL);
    lock_init(&lock);
}

void free_frame(void* frame){
    lock_acquire(&lock); 
    struct frame_table_elem to_find;
    to_find.frame = frame;
    struct hash_elem *h = hash_find(&frame_table, &(to_find.helem));
    struct frame_table_elem *elem = hash_entry(h, struct frame_table_elem, helem);
    hash_delete(&frame_table, &elem->helem);
    palloc_free_page(frame);
    free(elem);
    lock_release(&lock);
}

void* allocate_frame(enum palloc_flags flags, void* upage){
    lock_acquire(&lock);
    void *frame_page = palloc_get_page (PAL_USER | flags);
    if(frame_page == NULL) frame_page = evict_frame(upage);
    if(frame_page == NULL) PANIC("Swap is full, can not evict frame!!!");
    struct frame_table_elem* elem = malloc(sizeof(struct frame_table_elem));
    elem->t = thread_current();
    elem->frame = frame_page;
    elem->upage = upage;
    hash_insert(&frame_table, &elem->helem);
    lock_release(&lock);
    return frame_page;
}

void* evict_frame(void* upage){
    struct frame_table_elem* elem = frame_to_evict();
    size_t swap_index = swap_write(elem->frame);
    page_table_evict_page(elem->t->page_table, elem->upage, swap_index); 
    elem->t = thread_current();
    elem->upage = upage;
    return elem->frame;
}

struct frame_table_elem* frame_to_evict(){
    struct hash_iterator i;
    int it;
    for (it = 0 ; it < 2; it++){
        hash_first (&i, &frame_table);
        do {
            struct frame_table_elem *elem = hash_entry (hash_cur (&i), struct frame_table_elem, helem);
            if(elem->upage == NULL) continue;
            if(page_table_is_accessed(elem->t->page_table, elem->upage)){
                page_table_set_accessed(elem->t->page_table, elem->upage, false);
                continue;
            }
            return elem;
        }while (hash_next (&i));
    }
}

static unsigned hash_func(const struct hash_elem *elem, void *aux UNUSED){
    struct frame_table_elem *entry = hash_entry(elem, struct frame_table_elem, helem);
    return hash_bytes( &entry->frame, sizeof entry->frame );
}

static bool less_func(const struct hash_elem * a, const struct hash_elem *b, void *aux UNUSED){
    struct frame_table_elem *a_elem = hash_entry(a, struct frame_table_elem, helem);
    struct frame_table_elem *b_elem = hash_entry(b, struct frame_table_elem, helem);
    return a_elem->frame < b_elem->frame;
}