#include "lib/kernel/hash.h"
#include <stdio.h>
#include "vm/page.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"


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
    hash_insert(table, &elem->helem);
}
