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


struct hash * page_table_init(){
    return NULL;
}

void page_table_evict_page(struct hash * table, void *upage, size_t swap_index){}
bool page_table_is_accessed (struct hash *table, const void *upage){}
void page_table_set_accessed (struct hash *table, const void *upage, bool accessed){}

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
