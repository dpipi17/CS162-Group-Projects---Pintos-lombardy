#include "lib/kernel/hash.h"
#include <stdio.h>
#include "vm/page.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "vm/swap.h"

struct page_table_elem* search_in_table(struct hash * table, void *upage);
void write_in_file(struct file* file, void* upage , size_t offset, size_t size);
static unsigned hash_func(const struct hash_elem *elem, void *aux);
static bool less_func(const struct hash_elem * a, const struct hash_elem * b, void *aux);


struct hash * page_table_init(){
    struct hash* supp_table = (struct hash*)malloc(sizeof(struct hash));
    hash_init(supp_table, hash_func, less_func, NULL);
    return supp_table;
}

static void
destroy_func(struct hash_elem *elem, void *aux UNUSED)
{
  struct page_table_elem *entry = hash_entry(elem, struct page_table_elem, helem);

  if (entry->kpage != NULL) {
    free_frame(entry->kpage);
  } else if(entry->swap_index != -1) {
    swap_free(entry->swap_index);
  }

  free (entry);
}

void page_table_destroy (struct hash *table){
    hash_destroy(table, destroy_func);
    free(table);
}

bool page_table_set_page (struct hash *table, void *upage, void *kpage){
    upage = pg_round_down(upage);
    struct page_table_elem *elem = search_in_table(table, upage);
    if (elem == NULL) {
        struct page_table_elem* new_elem = malloc(sizeof(struct page_table_elem));
        new_elem->upage = upage;
        new_elem->kpage = kpage;
        new_elem->valid = true;
        new_elem->writeable = true;
        new_elem->accessed = false;
        new_elem->dirty = false;
        new_elem->offset = -1;
        new_elem->file = NULL;
        new_elem->not_evict = false;
        new_elem->swap_index = -1;
        hash_insert(table, new_elem);
        return true;
    } else {
        return false;
    }
}

void *page_table_get_page (struct hash *table, const void *upage){
    upage = pg_round_down(upage);
    struct page_table_elem *elem = search_in_table(table, upage);
    if (elem == NULL)
        return NULL;
    
    if (!elem->valid) {    
        elem->kpage = allocate_frame(PAL_USER | PAL_ZERO, upage);
        if (elem->file != NULL) {
            file_seek (elem->file, elem->offset);
            size_t n_read = file_read (elem->file, elem->kpage, elem->read_bytes_size);
            memset(elem->kpage + n_read, 0, PGSIZE - elem->read_bytes_size);
            elem->not_evict = true;
        } else if (elem->swap_index != -1) {
            swap_read(elem->swap_index, elem->kpage);
            elem->swap_index = -1;
        }       
        
        elem->valid = true;
        pagedir_set_page(thread_current()->pagedir, upage, elem->kpage, elem->writeable);
        // elem->dirty = false;
        //pagedir_set_dirty(thread_current()->pagedir, upage, elem->dirty);
    }

    return elem->kpage;
}

void page_table_clear_page (struct hash *table, void *upage){
    upage = pg_round_down(upage);
    struct page_table_elem *elem = search_in_table(table, upage);
    hash_delete(table, &elem->helem);
    free_frame(elem->kpage);
    free(elem);
}
bool page_table_is_dirty (struct hash *table, const void *upage){
    upage = pg_round_down(upage);
    struct page_table_elem *elem = search_in_table(table, upage);

    return elem->dirty;
}
void page_table_set_dirty (struct hash *table, const void *upage, bool dirty){
    upage = pg_round_down(upage);
    struct page_table_elem *elem = search_in_table(table, upage);
    elem->dirty = dirty;
}


bool page_table_is_accessed (struct hash *table, uint32_t * pagedir, const void *upage){
    upage = pg_round_down(upage);
    struct page_table_elem *elem = search_in_table(table, upage);
    return elem->accessed || pagedir_is_accessed(pagedir , upage);
}
void page_table_set_accessed (struct hash *table, uint32_t * pagedir,const void *upage, bool accessed){
    upage = pg_round_down(upage);
    struct page_table_elem *elem = search_in_table(table, upage);
    elem->accessed = accessed;
    pagedir_set_accessed(pagedir , upage , accessed);
}

void page_table_evict_page(struct hash *table, uint32_t * pagedir, void *upage, size_t swap_index){
    upage = pg_round_down(upage);
    struct page_table_elem *elem = search_in_table(table, upage);
    elem->dirty = elem->dirty || pagedir_is_dirty(pagedir , upage);
    elem->accessed = elem->accessed || pagedir_is_accessed(pagedir , upage);
    elem->valid = false;
    elem->swap_index = swap_index;
    elem->kpage = NULL;
    pagedir_clear_page(pagedir, upage);
}

void page_table_mmap(struct hash * table, void *upage, struct file * file, size_t offset, bool writeable, size_t read_bytes_size){
    upage = pg_round_down(upage);
    struct page_table_elem* elem = malloc(sizeof(struct page_table_elem));
    elem->upage = upage;
    elem->kpage = NULL;
    elem->valid = false;
    elem->writeable = writeable;
    elem->accessed = false;
    elem->dirty = false;
    elem->offset = offset;
    elem->file = file;
    elem->not_evict = false;
    elem->read_bytes_size = read_bytes_size;
    elem->swap_index = -1;
    hash_insert(table, &(elem->helem));
}

void page_table_unmap(struct hash * table, void *upage, size_t size) {
    upage = pg_round_down(upage);
    struct page_table_elem* elem = search_in_table(table , upage);
    if (elem == NULL) return;

    if(elem->valid && elem->kpage != NULL){
        if(elem->dirty || pagedir_is_dirty(thread_current()->pagedir , upage)) {
            write_in_file(elem->file, elem->upage , elem->offset, size);
        }
    }
    hash_delete(table, &(elem->helem));
}

void write_in_file(struct file* file, void* page , size_t offset, size_t size){
    //? maybe in loop?
    file = file_reopen(file);
    file_write_at(file, page , size, offset);
}

struct page_table_elem* search_in_table(struct hash * table, void *upage){
    upage = pg_round_down(upage);
    struct page_table_elem to_find;
    to_find.upage = upage;
    struct hash_elem *h = hash_find(table, &(to_find.helem));
    if (h == NULL) return NULL;
    struct page_table_elem *elem = hash_entry(h, struct page_table_elem, helem);
    return elem;
}



static unsigned hash_func(const struct hash_elem *elem, void *aux UNUSED){
    struct page_table_elem *entry = hash_entry(elem, struct page_table_elem, helem);
    return hash_int(entry->upage);
}

static bool less_func(const struct hash_elem * a, const struct hash_elem *b, void *aux UNUSED){
    struct page_table_elem *a_elem = hash_entry(a, struct page_table_elem, helem);
    struct page_table_elem *b_elem = hash_entry(b, struct page_table_elem, helem);
    return a_elem->upage < b_elem->upage;
}


// clean
// pintos -v -k -T 60 --qemu  --filesys-size=2 -p tests/vm/mmap-clean -a mmap-clean -p ../../tests/vm/sample.txt -a sample.txt --swap-size=4 -- -q  -f run mmap-clean < /dev/null 2> tests/vm/mmap-clean.errors > tests/vm/mmap-clean.output
// perl -I../.. ../../tests/vm/mmap-clean.ck tests/vm/mmap-clean tests/vm/mmap-clean.result


//exit
// pintos -v -k -T 60 --qemu  --filesys-size=2 -p tests/vm/mmap-exit -a mmap-exit -p tests/vm/child-mm-wrt -a child-mm-wrt --swap-size=4 -- -q  -f run mmap-exit < /dev/null 2> tests/vm/mmap-exit.errors > tests/vm/mmap-exit.output
// perl -I../.. ../../tests/vm/mmap-exit.ck tests/vm/mmap-exit tests/vm/mmap-exit.result

//parallel
// pintos -v -k -T 60 --qemu  --filesys-size=2 -p tests/vm/page-parallel -a page-parallel -p tests/vm/child-linear -a child-linear --swap-size=4 -- -q  -f run page-parallel < /dev/null 2> tests/vm/page-parallel.errors > tests/vm/page-parallel.output
// perl -I../.. ../../tests/vm/page-parallel.ck tests/vm/page-parallel tests/vm/page-parallel.result
