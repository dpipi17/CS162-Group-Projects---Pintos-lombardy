#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "lib/kernel/hash.h"
#include "threads/palloc.h"
#include "vm/frame.h"
#include "filesys/file.h"

struct page_table_elem{
    struct hash_elem helem;  
    void *upage; //Vritual Address;
    void *kpage; //Kernel Address; "frame"
    bool valid; //Whether Present in memory;
    bool writeable;
    bool accessed;
    bool dirty;
    size_t swap_index;
    struct file * file;
    size_t offset;
};

struct hash * page_table_init(void);
void page_table_destroy (struct hash *);
bool page_table_set_page (struct hash *, void *upage, void *kpage);
void *page_table_get_page (struct hash *, const void *upage);
void page_table_clear_page (struct hash *, void *upage);
bool page_table_is_dirty (struct hash *, const void *upage);
void page_table_set_dirty (struct hash *, const void *upage, bool dirty);
bool page_table_is_accessed (struct hash *, const void *upage);
void page_table_set_accessed (struct hash *, const void *upage, bool accessed);
void page_table_evict_page(struct hash *, void *upage, size_t swap_index); 
void page_table_mmap(struct hash *, void *upage, struct file * file, size_t offset, bool writeable);
void page_table_unmap(struct hash *, void *upage);

#endif