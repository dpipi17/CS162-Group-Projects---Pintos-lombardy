#ifndef FILESYS_BUFFER_CACHE_H
#define FILESYS_BUFFER_CACHE_H

#include "devices/block.h"
#include "filesys/filesys.h"

struct cache_node {
    block_sector_t sector;
    char buff[BLOCK_SECTOR_SIZE];
};

/**
 * API
 */
void cache_init(void);

void cache_read(block_sector_t sector, void * src);

size_t cache_write(block_sector_t sector, void * dst);

void cache_destroy(void);

#endif /* filesys/swap.h */