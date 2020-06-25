#include "filesys/buffer-cache.h"
#include "threads/synch.h"

static struct lock lock;

static struct cache_node cache_node_array[64];

// Helper functions headers
static struct cache_node * get_cache_node(block_sector_t sector);
static struct cache_node * evict_node(block_sector_t new_sector);


void cache_init() {
    size_t index;
    for (index = 0; index < 64; index++) {
        cache_node_array[index].sector = -1;
        cache_node_array[index].accessed = false;
        cache_node_array[index].dirty = false;
    }
    lock_init(&lock);
}

void cache_read(block_sector_t sector, void * dst) {
    lock_acquire(&lock);
    
    struct cache_node * node;
    node = get_cache_node(sector);
    
    memcpy(dst, node->buff, BLOCK_SECTOR_SIZE);
    node->accessed = true;

    lock_release(&lock);
}

size_t cache_write(block_sector_t sector, void * src) {
    lock_acquire(&lock);
    struct cache_node * node;
    node = get_cache_node(sector);

    memcpy(node->buff, src, BLOCK_SECTOR_SIZE);
    node->accessed = true;
    node->dirty = true;
    
    lock_release(&lock);
}

void cache_destroy(void) {
    lock_acquire(&lock);
    size_t index;
    for (index = 0; index < 64; index++) {
        if (cache_node_array[index].sector != -1 && cache_node_array[index].dirty) {
            block_write(fs_device, cache_node_array[index].sector, cache_node_array[index].buff);
            cache_node_array[index].dirty = false;
        }
    }
    lock_release(&lock);
}


// ----------------------------------------Helper Functions------------------------------------------
static struct cache_node * get_cache_node(block_sector_t sector) {
    size_t index;
    for (index = 0; index < 64; index++) {
        if (cache_node_array[index].sector == sector) {
            return &cache_node_array[index];
        }
    }

    for (index = 0; index < 64; index++) {
        if (cache_node_array[index].sector == -1) {
            cache_node_array[index].sector = sector;
            return &cache_node_array[index];
        }
    }

    return evict_node(sector);
}

static struct cache_node * evict_node(block_sector_t new_sector) {
    size_t index;
    index = 0;

    struct cache_node * node_to_evict;

    while (1) {
        index %= 64;

        if (cache_node_array[index].accessed) {
            cache_node_array[index].accessed = false;
            index++;
            continue;
        }

        node_to_evict = &cache_node_array[index];
        break;
    }

    if (node_to_evict->dirty) {
        block_write(fs_device, node_to_evict->sector, node_to_evict->buff);
    }

    node_to_evict->dirty = false;
    node_to_evict->sector = new_sector;
    block_read(fs_device, new_sector, node_to_evict->buff);
    
    return node_to_evict;
}
