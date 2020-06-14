#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "lib/kernel/hash.h"
#include "threads/palloc.h"

struct frame_table_elem{
    struct hash_elem helem;   
    bool not_evict; 
    void *frame;
    void *upage;
    struct thread *t;      
};

static struct hash frame_table;

void frame_init(void);
void free_frame(void* frame);
void* allocate_frame(enum palloc_flags flags, void* upage);
void* evict_frame(void* upage);
void change_evict_status(void * frame, bool new_status);
void * wrapper_helper(bool allocate, enum palloc_flags flags, void* upage, struct hash *table, const void *upage2);

#endif