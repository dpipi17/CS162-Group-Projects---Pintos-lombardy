#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "lib/kernel/hash.h"
#include "threads/palloc.h"

struct frame_table_elem{
    struct hash_elem helem;    
    void *frame;
    struct thread *t;      
};

static struct hash frame_table;

void frame_init(void);
void free_frame(void* frame);
void* allocate_frame(enum palloc_flags flags);
void* evict_frame();

#endif