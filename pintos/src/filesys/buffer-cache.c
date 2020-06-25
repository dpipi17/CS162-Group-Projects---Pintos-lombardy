#include "filesys/buffer-cache.h"
#include "threads/synch.h"

static struct lock lock;

static struct cache_node cache_node_array[64];


void cache_init() {
    size_t index;
    for (index = 0; index < 64; index++) {
        cache_node_array[index].sector = -1;
    }
    lock_init(&lock);
}

void cache_read(block_sector_t sector, void * src) {
    lock_acquire(&lock);
    block_read(fs_device, sector, src);
    lock_release(&lock);
}

size_t cache_write(block_sector_t sector, void * dst) {
    lock_acquire(&lock);
    block_write(fs_device, sector, dst);
    lock_release(&lock);
}

void cache_destroy(void) {
    lock_acquire(&lock);
    size_t index;
    for (index = 0; index < 64; index++) {

        if (cache_node_array[index].sector != -1) {
            block_write(fs_device, cache_node_array[index].sector, cache_node_array[index].buff);
        }
    }
    lock_release(&lock);
}