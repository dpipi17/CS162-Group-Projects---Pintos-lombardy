#include "vm/swap.h"
#include "threads/vaddr.h"

/**
 * This function called only once and it inits swap table.
 */
void swap_init() {
    global_swap_block = block_get_role(BLOCK_SWAP);

    size_t bit_map_size = block_size(global_swap_block);
    swap_blocks_bitmap = bitmap_create(bit_map_size);
    bitmap_set_all(swap_blocks_bitmap, true);
}

/**
 * This function reads info from swap and writes it into frame.
 * index is parameter to find out from which position read content.
 * frame parameter is memory block where function writes bytes.
 * after all, function frees 8 blocks started from index in swap slot. 
 */
void swap_read(size_t index, void * frame) {
    size_t i;
    for (i = 0; i < 8; i++) {
        block_read(global_swap_block, index + i, frame + (i * BLOCK_SECTOR_SIZE));
    }
    update_bitmap(index, true);
}

/**
 * This function reads info from frame and writes it into swap.
 * frame parameter is memory block from where function reads content.
 * if there is no space in swap, function panics kernel.
 * after all, function marks 8 blocks started from index in swap slot as used. 
 */
size_t swap_write(void * frame) {
    size_t result_index;
    result_index = bitmap_scan(swap_blocks_bitmap, 0, 8, true);

    if (result_index == BITMAP_ERROR) {
        PANIC("Error: There is no space in swap slot.");
    }

    size_t i;
    for (i = 0; i < 8; i++) {
        block_write(global_swap_block, result_index + i, frame + (i * BLOCK_SECTOR_SIZE));
    }
    update_bitmap(result_index, false);

    return result_index;
}

/**
 * This function frees memory blocks started from index.
 */
void swap_free(size_t index) {
    update_bitmap(index, true);
}

/**
 * This is Helper function.
 * It updates bit map started from index using value parameter.
 */
void update_bitmap(size_t index, bool value) {
    size_t i;
    for (i = 0; i < 8; i++) {
        bitmap_set(swap_blocks_bitmap, index + i, value);
    }
}