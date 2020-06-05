#include <bitmap.h>
#include "devices/block.h"

static struct block * global_swap_block;
static struct bitmap * swap_blocks_bitmap;

/**
 * API
 */
void swap_init(void);

void swap_read(size_t index, void * frame);

size_t swap_write(void * frame);

void swap_free(size_t index);

/**
 * Helper functions
 */
void update_bitmap(size_t index, bool value);