#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/buffer-cache.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define DIRECT_BLOCKS 123
#define INDIRECT_BLOCKS 128


/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    block_sector_t direct_blocks[DIRECT_BLOCKS];    /* Direct blocks. */
    block_sector_t indirect_blocks;                 /* Single ptr for indirect blocks */
    block_sector_t doubly_indirect_blocks;          /* Single ptr for doubly indirect blocks */
    bool is_dir;
    off_t length;                                   /* File size in bytes. */
    unsigned magic;                                 /* Magic number. */
    //uint32_t unused[125];                           /* Not used. */
  };

struct indirect_blocks_t {
  block_sector_t blocks[INDIRECT_BLOCKS];
};

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
  };
  
bool inode_allocate (struct inode_disk* inode_disk, off_t length);
bool inode_block_allocate (block_sector_t* block_sector);
bool inode_indirect_blocks_allocate (block_sector_t* indirect_blocks_sector, size_t num_sectors);
bool inode_doubly_indirect_blocks_allocate (block_sector_t* doubly_indirect_blocks_sector, size_t num_sectors);
void inode_destroy (struct inode* inode);
void inode_indirect_blocks_destroy (block_sector_t* indirect_blocks_sector, size_t num_sectors);
void inode_doubly_indirect_blocks_destroy (block_sector_t* doubly_indirect_blocks_sector, size_t num_sectors);

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos)
{
  ASSERT (inode != NULL);
  block_sector_t sector = -1;
  struct inode_disk inode_disk = inode->data;

  if (0 <= pos && pos < inode_disk.length) {
    off_t index = pos / BLOCK_SECTOR_SIZE;
    
    if (index < DIRECT_BLOCKS) {
      sector = inode_disk.direct_blocks[index];
    } else if (DIRECT_BLOCKS + INDIRECT_BLOCKS) {
      index -= DIRECT_BLOCKS;
      struct indirect_blocks_t indirect_blocks;
      cache_read(inode_disk.indirect_blocks, &indirect_blocks);
      sector = indirect_blocks.blocks[index];
    } else {
      index -= DIRECT_BLOCKS + INDIRECT_BLOCKS;
      struct indirect_blocks_t indirect_blocks;
      off_t double_indirect_index = index / INDIRECT_BLOCKS;
      off_t indirect_index = index % INDIRECT_BLOCKS;
      cache_read(inode_disk.doubly_indirect_blocks, &indirect_blocks);
      cache_read(indirect_blocks.blocks[double_indirect_index], &indirect_blocks);
      sector = indirect_blocks.blocks[indirect_index];
    }
  }

  return sector;
}

bool inode_allocate (struct inode_disk* inode_disk, off_t length) {
  if (length < 0)
    return false;
  
  size_t num_sectors_left = bytes_to_sectors(length);
  size_t cur_num_sectors = num_sectors_left < DIRECT_BLOCKS ? num_sectors_left : DIRECT_BLOCKS;
  size_t i;
  for (i = 0; i < cur_num_sectors; i++) {
    if (!inode_disk->direct_blocks[i])
      if (!inode_block_allocate(&inode_disk->direct_blocks[i]))
        return false;
  }
  if ((num_sectors_left -= cur_num_sectors) == 0)
    return true;

  cur_num_sectors = num_sectors_left < INDIRECT_BLOCKS ? num_sectors_left : INDIRECT_BLOCKS;
  if (!inode_indirect_blocks_allocate(&inode_disk->indirect_blocks, cur_num_sectors))
    return false;
  if ((num_sectors_left -= cur_num_sectors) == 0)
    return true;
  
  cur_num_sectors = num_sectors_left < INDIRECT_BLOCKS * INDIRECT_BLOCKS ? 
    num_sectors_left : INDIRECT_BLOCKS * INDIRECT_BLOCKS;
  if (!inode_doubly_indirect_blocks_allocate(&inode_disk->doubly_indirect_blocks, cur_num_sectors))
    return false;
  if ((num_sectors_left -= cur_num_sectors) == 0)
    return true;

  // length of sectors limited
  ASSERT (num_sectors_left == 0);
}

bool inode_block_allocate (block_sector_t* block_sector) {
  static char zeros[BLOCK_SECTOR_SIZE];
  
  /* Could not alocate sector */
  if (!free_map_allocate(1, block_sector))
    return false;
  
  cache_write(*block_sector, zeros);
  return true;
}

bool inode_indirect_blocks_allocate (block_sector_t* indirect_blocks_sector, size_t num_sectors) {
  if (!(*indirect_blocks_sector))
    if (!inode_block_allocate(indirect_blocks_sector))
      return false;
  
  struct indirect_blocks_t indirect_blocks;
  cache_read(*indirect_blocks_sector, &indirect_blocks);

  size_t i;
  for (i = 0; i < num_sectors; i++) {
    if (!indirect_blocks.blocks[i])
      if (!inode_block_allocate(&indirect_blocks.blocks[i]))
        return false;
  }

  cache_write(*indirect_blocks_sector, &indirect_blocks);
  return true;
}

bool inode_doubly_indirect_blocks_allocate (block_sector_t* doubly_indirect_blocks_sector, size_t num_sectors) {
  if (!(*doubly_indirect_blocks_sector))
    if (!inode_block_allocate(doubly_indirect_blocks_sector))
      return false;
  
  struct indirect_blocks_t doubly_indirect_blocks;
  cache_read(*doubly_indirect_blocks_sector, &doubly_indirect_blocks);

  size_t num_indirect_sectors = DIV_ROUND_UP(num_sectors, INDIRECT_BLOCKS);
  size_t i;
  for (i = 0; i < num_indirect_sectors; i++) {
    size_t cur_num_sectors = num_sectors < INDIRECT_BLOCKS ? num_sectors : INDIRECT_BLOCKS;
    if (!inode_indirect_blocks_allocate(&doubly_indirect_blocks.blocks[i], cur_num_sectors))
      return false;
    num_sectors -= cur_num_sectors;
  }

  cache_write(*doubly_indirect_blocks_sector, &doubly_indirect_blocks);
  return true;
}

void inode_destroy (struct inode* inode) {
  struct inode_disk inode_disk = inode->data;

  if (inode_disk.length < 0)
    return;
  
  size_t num_sectors_left = bytes_to_sectors(inode_disk.length);
  size_t cur_num_sectors = num_sectors_left < DIRECT_BLOCKS ? num_sectors_left : DIRECT_BLOCKS;
  size_t i;
  for (i = 0; i < cur_num_sectors; i++) {
    free_map_release(inode_disk.direct_blocks[i], 1);
  }
  if ((num_sectors_left -= cur_num_sectors) == 0)
    return;

  cur_num_sectors = num_sectors_left < INDIRECT_BLOCKS ? num_sectors_left : INDIRECT_BLOCKS;
  inode_indirect_blocks_destroy(&inode_disk.indirect_blocks, cur_num_sectors);
  if ((num_sectors_left -= cur_num_sectors) == 0)
    return;
  
  cur_num_sectors = num_sectors_left < INDIRECT_BLOCKS * INDIRECT_BLOCKS ? 
    num_sectors_left : INDIRECT_BLOCKS * INDIRECT_BLOCKS;
  inode_doubly_indirect_blocks_destroy(&inode_disk.doubly_indirect_blocks, cur_num_sectors);

  // length of sectors limited
  ASSERT (num_sectors_left == 0);
}

void inode_indirect_blocks_destroy (block_sector_t* indirect_blocks_sector, size_t num_sectors) {
  struct indirect_blocks_t indirect_blocks;
  cache_read(*indirect_blocks_sector, &indirect_blocks);

  size_t i;
  for (i = 0; i < num_sectors; i++) {
    free_map_release(indirect_blocks.blocks[i], 1);
  }

  free_map_release(*indirect_blocks_sector, 1);
}

void inode_doubly_indirect_blocks_destroy (block_sector_t* doubly_indirect_blocks_sector, size_t num_sectors) {
  struct indirect_blocks_t doubly_indirect_blocks;
  cache_read(*doubly_indirect_blocks_sector, &doubly_indirect_blocks);

  size_t num_indirect_sectors = DIV_ROUND_UP(num_sectors, INDIRECT_BLOCKS);
  size_t i;
  for (i = 0; i < num_indirect_sectors; i++) {
    size_t cur_num_sectors = num_sectors < INDIRECT_BLOCKS ? num_sectors : INDIRECT_BLOCKS;
    inode_indirect_blocks_destroy(&doubly_indirect_blocks.blocks[i], cur_num_sectors);
    num_sectors -= cur_num_sectors;
  }

  free_map_release(*doubly_indirect_blocks_sector, 1);
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void)
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, bool is_dir)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      disk_inode->length = length;
      disk_inode->is_dir = is_dir;
      disk_inode->magic = INODE_MAGIC;
      if (inode_allocate(disk_inode, length)) {
        cache_write(sector, disk_inode);
        success = true;
      }
      free (disk_inode);
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e))
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector)
        {
          inode_reopen (inode);
          return inode;
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  cache_read(inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode)
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);

      /* Deallocate blocks if removed. */
      if (inode->removed)
        {
          free_map_release (inode->sector, 1);
          inode_destroy(inode);
        }

      free (inode);
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode)
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset)
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0)
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          cache_read(sector_idx, buffer + bytes_read);
        }
      else
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL)
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          cache_read(sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset)
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  if (offset + size > inode->data.length) {
    if (!inode_allocate(&inode->data, offset + size)) {
      return 0;
    }

    inode->data.length = offset + size;
    cache_write(inode->sector, &inode->data);
  }

  while (size > 0)
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          cache_write(sector_idx, buffer + bytes_written);
        }
      else
        {
          /* We need a bounce buffer. */
          if (bounce == NULL)
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) {
            cache_read(sector_idx, bounce);
          } else {
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          }
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          cache_write(sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode)
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode)
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}

bool is_directory (struct inode *inode){
  return inode->data.is_dir;
}

bool inode_is_removed(struct inode * inode){
  return inode->removed;
}
