#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "devices/block.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
  if (pos < inode->data->length)
    return inode->data->start + pos / BLOCK_SECTOR_SIZE;
  else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;
struct lock inode_list_lock;

static struct list buffer_cache;
static struct lock global_cache_lock;
static struct lock free_lock;

static int cache_hits;
static int cache_accesses;

/* Initializes the inode module. */
void inode_init(void) {

  list_init(&open_inodes);

  //Initialize buffer cache
  list_init(&buffer_cache);
  lock_init(&global_cache_lock);
  lock_init(&free_lock);
  for (int i = 0; i < 64; i++) {
    struct buffer_cache_elem* block = malloc(sizeof(struct buffer_cache_elem));
    block->valid = false;
    block->sector = 0;
    block->dirty = false;
    lock_init(&block->block_lock);
    list_push_front(&buffer_cache, &block->elem);
  }
}
/*
let go of global cache lock:
every eviction has been written to the cache somehow
*/

/* Reads information at sector through the buffer cache into the buffer */
void cache_read(block_sector_t sector, const void* buffer, int chunk_size, int sector_ofs) {
  //iterate through buffer_cache to check for block
  struct list_elem* e;
  lock_acquire(&global_cache_lock);
  cache_accesses = cache_accesses + 1;
  for (e = list_begin(&buffer_cache); e != list_end(&buffer_cache); e = list_next(e)) {
    struct buffer_cache_elem* block = list_entry(e, struct buffer_cache_elem, elem);
    if (block->sector == sector && block->valid) {
      lock_acquire(&block->block_lock);
      lock_release(&global_cache_lock);
      /* Copy block->buffer into buffer */

      memcpy(buffer, (uint8_t*)block->buffer + sector_ofs, chunk_size);
      lock_release(&block->block_lock);
      //update position of block
      lock_acquire(&global_cache_lock);
      list_remove(&block->elem);
      list_push_front(&buffer_cache, &block->elem);
      cache_hits = cache_hits + 1;
      lock_release(&global_cache_lock);
      return;
    }
  }
  //lock_release(&global_cache_lock);
  //if not in cache, evict if necessary and load in the block

  for (e = list_begin(&buffer_cache); e != list_end(&buffer_cache); e = list_next(e)) {
    struct buffer_cache_elem* block = list_entry(e, struct buffer_cache_elem, elem);
    if (!block->valid) {
      /* Found invalid block we can write to */
      block->valid = true;
      block->sector = sector;
      block->dirty = false;
      block_read(fs_device, sector, block->buffer);
      memcpy(buffer, (uint8_t*)block->buffer + sector_ofs, chunk_size);
      list_remove(&block->elem);
      list_push_front(&buffer_cache, &block->elem);
      lock_release(&global_cache_lock);
      return;
    }
  }

  /* Did not find an invalid block to write to: must evict */
  cache_evict();

  //lock_acquire(&global_cache_lock);
  //load in new block
  struct list_elem* element = list_pop_back(&buffer_cache);
  struct buffer_cache_elem* block = list_entry(element, struct buffer_cache_elem, elem);
  list_push_front(&buffer_cache, &block->elem);
  lock_init(&block->block_lock);
  block->valid = true;
  block->sector = sector;
  block->dirty = false;
  block_read(fs_device, sector, block->buffer);
  memcpy(buffer, (uint8_t*)block->buffer + sector_ofs, chunk_size);
  //read from block
  lock_release(&global_cache_lock);
}

/* Write sector SECTOR to cache from buffer, which must contain BLOCK_SECTOR_SIZE bytes.  */
void cache_write(block_sector_t sector, const void* buffer, int chunk_size, int sector_ofs) {
  //iterate through buffer_cache to check for block

  struct list_elem* e;
  lock_acquire(&global_cache_lock);
  cache_accesses = cache_accesses + 1;
  for (e = list_begin(&buffer_cache); e != list_end(&buffer_cache); e = list_next(e)) {
    struct buffer_cache_elem* block = list_entry(e, struct buffer_cache_elem, elem);
    if (block->sector == sector && block->valid) {
      lock_acquire(&block->block_lock);
      lock_release(&global_cache_lock);
      memcpy((uint8_t*)block->buffer + sector_ofs, buffer, chunk_size);
      block->dirty = true;
      lock_release(&block->block_lock);

      //update position of block
      lock_acquire(&global_cache_lock);
      list_remove(&block->elem);
      list_push_front(&buffer_cache, &block->elem);
      cache_hits = cache_hits + 1;
      lock_release(&global_cache_lock);
      return;
    }
  }
  //if not in cache, evict if necessary and load in the block
  for (e = list_begin(&buffer_cache); e != list_end(&buffer_cache); e = list_next(e)) {
    struct buffer_cache_elem* block = list_entry(e, struct buffer_cache_elem, elem);
    if (!block->valid) {
      /* Found invalid block we can write to */
      block->valid = true;
      block->sector = sector;
      block->dirty = true;
      memcpy((uint8_t*)block->buffer + sector_ofs, buffer, chunk_size);
      list_remove(&block->elem);
      list_push_front(&buffer_cache, &block->elem);
      lock_release(&global_cache_lock);
      return;
    }
  }

  /* Did not find an invalid block to write to: must evict */
  cache_evict();

  //load in new block
  struct list_elem* element = list_pop_back(&buffer_cache);
  struct buffer_cache_elem* block = list_entry(element, struct buffer_cache_elem, elem);
  list_push_front(&buffer_cache, &block->elem);
  lock_init(&block->block_lock);
  block->valid = true;
  block->sector = sector;
  block->dirty = true;
  block_read(fs_device, sector, block->buffer);
  memcpy((uint8_t*)block->buffer + sector_ofs, buffer, chunk_size);
  lock_release(&global_cache_lock);
}

void cache_evict() {
  // lock_acquire(&global_cache_lock);
  struct list_elem* element = list_back(&buffer_cache);
  struct buffer_cache_elem* block = list_entry(element, struct buffer_cache_elem, elem);
  if (block->dirty && block->valid) {
    //write back to disk
    block_write(fs_device, block->sector, block->buffer);
    // block->dirty
  }

  //free(block);
  // lock_release(&global_cache_lock);
}

void cache_flush() {
  //Evict all the blocks and write if necessary.
  lock_acquire(&global_cache_lock);
  struct list_elem* e;
  for (e = list_begin(&buffer_cache); e != list_end(&buffer_cache); e = list_next(e)) {
    struct buffer_cache_elem* block = list_entry(e, struct buffer_cache_elem, elem);
    if (block->dirty && block->valid) {
      lock_acquire(&block->block_lock);
      block_write(fs_device, block->sector, block->buffer);
      lock_release(&block->block_lock);
    }
    block->valid = false;
    //free(e);
  }
  lock_release(&global_cache_lock);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length) {
  //lock_acquire(&free_lock);
  struct inode_disk* disk_inode = NULL;
  bool success = false;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof *disk_inode);
  if (disk_inode != NULL) {
    size_t sectors = bytes_to_sectors(length);
    disk_inode->length = length;
    disk_inode->magic = INODE_MAGIC;
    if (free_map_allocate(sectors, &disk_inode->start)) {
      /* Write sector SECTOR to fs_device from disk_inode, which must contain BLOCK_SECTOR_SIZE bytes.  */
      // block_write(fs_device, sector, disk_inode);
      cache_write(sector, disk_inode, BLOCK_SECTOR_SIZE, 0);
      if (sectors > 0) {
        static char zeros[BLOCK_SECTOR_SIZE];
        size_t i;

        for (i = 0; i < sectors; i++)
          //block_write(fs_device, disk_inode->start + i, zeros);
          cache_write(disk_inode->start + i, zeros, BLOCK_SECTOR_SIZE, 0);
      }
      success = true;
    }
    free(disk_inode);
  }
  //lock_release(&free_lock);
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
  struct list_elem* e;
  struct inode* inode;

  // lock the inode list
  //lock_acquire(&inode_list_lock);
  /* Check whether this inode is already open. */
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    // lock_acquire(&inode->lock);
    if (inode->sector == sector) {
      inode_reopen(inode);
      // lock_release(&inode->lock);
      return inode;
    }
    // lock_release(&inode->lock);
  }

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front(&open_inodes, &inode->elem);
  // release the lock
  // lock_release(&inode_list_lock);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  //block_read(fs_device, inode->sector, &inode->data);
  cache_read(inode->sector, &inode->data, BLOCK_SECTOR_SIZE, 0);
  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  if (inode != NULL) {
    // lock_acquire(&inode->lock);
    inode->open_cnt++;
    // lock_release(&inode->lock);
  }
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode* inode) { return inode->sector; }

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode* inode) {
  /* Ignore null pointer. */
  if (inode == NULL)
    return;
  // aqcuire inode lock
  // lock_acquire(&inode->lock);
  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0) {
    /* Remove from inode list and release lock. */
    // lock_acquire(&inode_list_lock);
    list_remove(&inode->elem);
    // lock_release(&inode_list_lock);

    /* Deallocate blocks if removed. */
    if (inode->removed) {
      free_map_release(inode->sector, 1);
      free_map_release(inode->data->start, bytes_to_sectors(inode->data->length));
    }
    // release ionde lock
    // lock_release(&inode->lock);
    free(inode);
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
  ASSERT(inode != NULL);
  // aqcuire inode lock
  // lock_acquire(&inode->lock);
  inode->removed = true;
  // release lock
  // lock_release(&inode->lock);
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;

  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    // acquire inode lock
    // lock_acquire(&inode->lock);
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    // release inode lock
    // lock_release(&inode->lock);
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Read full sector directly into caller's buffer. */
      cache_read(sector_idx, buffer + bytes_read, BLOCK_SECTOR_SIZE, 0);
    } else {

      cache_read(sector_idx, buffer + bytes_read, chunk_size, sector_ofs);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;

  // acquire inode lock
  // lock_acquire(&inode->lock);
  if (inode->deny_write_cnt) {
    // lock_release(&inode->lock);
    return 0;
  }
  // inode_resize(inode, offset + size);
  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    // release inode lock
    // lock_release(&inode->lock);
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Write full sector directly to disk. */
      //block_write(fs_device, sector_idx, buffer + bytes_written);
      cache_write(sector_idx, buffer + bytes_written, BLOCK_SECTOR_SIZE, 0);
    } else {
      cache_write(sector_idx, buffer + bytes_written, chunk_size, sector_ofs);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {
  // acquire inode lock
  // lock_acquire(&inode->lock);
  inode->deny_write_cnt++;
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  // release inode lock
  // lock_release(&inode->lock);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  // acquire inode lock
  // lock_acquire(&inode->lock);
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
  // release inode lock
  // lock_release(&inode->lock);
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode* inode) { return inode->data.length; }

float get_buffer_accesses() { return cache_accesses; }

float get_buffer_hits() { return cache_hits; }

long get_device_writes() { return get_writes(fs_device); }
