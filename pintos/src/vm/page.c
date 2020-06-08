#include "lib/kernel/hash.h"
#include <stdio.h>
#include "vm/page.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

struct page_table_elem* search_in_table(struct hash * table, void *upage);
void write_in_file(struct file* file, void* upage , size_t offset, size_t size);
static unsigned hash_func(const struct hash_elem *elem, void *aux);
static bool less_func(const struct hash_elem * a, const struct hash_elem * b, void *aux);


struct hash * page_table_init(){
    struct hash* supp_table = (struct hash*)malloc(sizeof(int));
    hash_init(thread_current()->page_table, hash_func, less_func, NULL);
    return NULL;
}

void page_table_destroy (struct hash *table){
    
}

bool page_table_set_page (struct hash *table, void *upage, void *kpage){
    struct page_table_elem to_find;
    to_find.upage = upage;
    struct hash_elem *h = hash_find(thread_current()->page_table, &(to_find.helem));
    struct page_table_elem *elem = hash_entry(h, struct page_table_elem, helem);
}

void *page_table_get_page (struct hash *table, const void *upage){
    struct page_table_elem to_find;
    to_find.upage = upage;
    struct hash_elem *h = hash_find(thread_current()->page_table, &(to_find.helem));
    struct page_table_elem *elem = hash_entry(h, struct page_table_elem, helem);
    return elem->kpage;
}
void page_table_clear_page (struct hash *table, void *upage){
    struct page_table_elem to_find;
    to_find.upage = upage;
    struct hash_elem *h = hash_find(thread_current()->page_table, &(to_find.helem));
    struct page_table_elem *elem = hash_entry(h, struct page_table_elem, helem);
    hash_delete(thread_current()->page_table, &elem->helem);
    free_frame(elem->kpage);
    free(elem);
}
bool page_table_is_dirty (struct hash *table, const void *upage){
    struct page_table_elem to_find;
    to_find.upage = upage;
    struct hash_elem *h = hash_find(thread_current()->page_table, &(to_find.helem));
    struct page_table_elem *elem = hash_entry(h, struct page_table_elem, helem);
    return elem->dirty;
}
void page_table_set_dirty (struct hash *table, const void *upage, bool dirty){
    struct page_table_elem to_find;
    to_find.upage = upage;
    struct hash_elem *h = hash_find(thread_current()->page_table, &(to_find.helem));
    struct page_table_elem *elem = hash_entry(h, struct page_table_elem, helem);
    elem->dirty = dirty;
}


bool page_table_is_accessed (struct hash *table, const void *upage){
    struct page_table_elem to_find;
    to_find.upage = upage;
    struct hash_elem *h = hash_find(thread_current()->page_table, &(to_find.helem));
    struct page_table_elem *elem = hash_entry(h, struct page_table_elem, helem);
    return elem->accessed;
}
void page_table_set_accessed (struct hash *table, const void *upage, bool accessed){
    struct page_table_elem to_find;
    to_find.upage = upage;
    struct hash_elem *h = hash_find(thread_current()->page_table, &(to_find.helem));
    struct page_table_elem *elem = hash_entry(h, struct page_table_elem, helem);
    elem->accessed = accessed;
}

void page_table_evict_page(struct hash *table, void *upage, size_t swap_index){
    struct page_table_elem to_find;
    to_find.upage = upage;
    struct hash_elem *h = hash_find(thread_current()->page_table, &(to_find.helem));
    struct page_table_elem *elem = hash_entry(h, struct page_table_elem, helem);
    elem->valid = false;
    elem->swap_index = swap_index;
}

void page_table_mmap(struct hash * table, void *upage, struct file * file, size_t offset, bool writeable){
    struct page_table_elem* elem = malloc(sizeof(struct page_table_elem));
    elem->upage = upage;
    elem->kpage = NULL;
    elem->valid = true;
    elem->writeable = writeable;
    elem->accessed = false;
    elem->dirty = false;
    elem->offset = offset;
    elem->file = file;
    hash_insert(table, &(elem->helem));
}

void page_table_unmap(struct hash * table, void *upage){
    struct page_table_elem* elem = search_in_table(table , upage);
    if(elem->valid){
        if(elem->dirty) 
            write_in_file(elem->file, elem->upage , elem->offset, PGSIZE);
        free_frame(elem->kpage);
    }else{
        if (elem->dirty) {
            void *page = allocate_frame(PAL_USER, NULL);
            swap_read(elem->swap_index, page);
            write_in_file(elem->file, page, elem->offset, PGSIZE);
            free_frame(page);
        } else swap_free (elem->swap_index);
    }
    hash_delete(table, &(elem->helem));
}

void write_in_file(struct file* file, void* page , size_t offset, size_t size){
    //? maybe in loop?
    file_write_at(file, page , size, offset);
}

struct page_table_elem* search_in_table(struct hash * table, void *upage){
    struct page_table_elem to_find;
    to_find.upage = upage;
    struct hash_elem *h = hash_find(&table, &(to_find.helem));
    struct page_table_elem *elem = hash_entry(h, struct page_table_elem, helem);
    return elem;
}



static unsigned hash_func(const struct hash_elem *elem, void *aux UNUSED){
    struct page_table_elem *entry = hash_entry(elem, struct page_table_elem, helem);
    return hash_bytes( &entry->upage, sizeof entry->upage );
}

static bool less_func(const struct hash_elem * a, const struct hash_elem *b, void *aux UNUSED){
    struct page_table_elem *a_elem = hash_entry(a, struct page_table_elem, helem);
    struct page_table_elem *b_elem = hash_entry(b, struct page_table_elem, helem);
    return a_elem->upage < b_elem->upage;
}