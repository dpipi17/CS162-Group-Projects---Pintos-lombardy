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