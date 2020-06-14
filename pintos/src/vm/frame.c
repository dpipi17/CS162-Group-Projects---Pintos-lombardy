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
    if (!lock_held_by_current_thread(&lock))
        lock_acquire(&lock); 
    struct frame_table_elem to_find;
    to_find.frame = frame;
    struct hash_elem *h = hash_find(&frame_table, &(to_find.helem));
    if (h != NULL) {
        struct frame_table_elem *elem = hash_entry(h, struct frame_table_elem, helem);
        if (pagedir_get_page(elem->t->pagedir, elem->upage) == NULL) {
            palloc_free_page(frame);
        }
        hash_delete(&frame_table, &elem->helem);
        free(elem);
    }
    if (lock_held_by_current_thread(&lock))
        lock_release(&lock);
}

void* allocate_frame(enum palloc_flags flags, void* upage){
    void *frame_page = palloc_get_page (PAL_USER | flags);
    if(frame_page == NULL) frame_page = evict_frame(upage);
    if(frame_page == NULL) PANIC("Swap is full, can not evict frame!!!");
    struct frame_table_elem* elem = malloc(sizeof(struct frame_table_elem));
    elem->t = thread_current();
    elem->frame = frame_page;
    elem->upage = upage;
    elem->not_evict = true;
    hash_insert(&frame_table, &elem->helem);
    return frame_page;
}

void* evict_frame(void* upage){
    struct frame_table_elem* elem = frame_to_evict();
    if (elem == NULL) {
        return NULL;
    }
    size_t swap_index = swap_write(elem->frame);
    page_table_evict_page(elem->t->page_table, elem->t->pagedir, elem->upage, swap_index); 
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
            if(page_table_is_accessed(elem->t->page_table, elem->t->pagedir,elem->upage)){
                page_table_set_accessed(elem->t->page_table, elem->t->pagedir, elem->upage, false);
                continue;
            }

            if (elem->not_evict) {
                continue;
            }

            return elem;
        }while (hash_next (&i));
    }
    return NULL;
}

void change_evict_status(void * frame, bool new_status) {
    if (!lock_held_by_current_thread(&lock))
        lock_acquire(&lock); 
    struct frame_table_elem to_find;
    to_find.frame = frame;
    struct hash_elem *h = hash_find(&frame_table, &(to_find.helem));
    if (h != NULL) {
        struct frame_table_elem *elem = hash_entry(h, struct frame_table_elem, helem);
        elem->not_evict = new_status;
    }
    if (lock_held_by_current_thread(&lock))
        lock_release(&lock); 
}

static unsigned hash_func(const struct hash_elem *elem, void *aux UNUSED){
    struct frame_table_elem *entry = hash_entry(elem, struct frame_table_elem, helem);
    return hash_int(entry->frame);
}

static bool less_func(const struct hash_elem * a, const struct hash_elem *b, void *aux UNUSED){
    struct frame_table_elem *a_elem = hash_entry(a, struct frame_table_elem, helem);
    struct frame_table_elem *b_elem = hash_entry(b, struct frame_table_elem, helem);
    return a_elem->frame < b_elem->frame;
}

void * get_frame_wrapper(bool allocate, enum palloc_flags flags, void* upage, struct hash *table) {
    if (!lock_held_by_current_thread(&lock))
        lock_acquire(&lock);
    
    if (allocate) {
        return allocate_frame(flags, upage);
    } else {
        return page_table_get_page(table, upage);
    }

    if (lock_held_by_current_thread(&lock))
        lock_release(&lock); 
}