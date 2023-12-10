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
#define INDIRECT_PTRS 128

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  // block_sector_t start; /* First data sector. */
  off_t length;   /* File size in bytes. */
  unsigned magic; /* Magic number. */
  block_sector_t direct[12];
  block_sector_t indirect;
  block_sector_t double_indirect;
  uint32_t unused[112]; /* Not used. */
};

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

/* In-memory inode. */
struct inode {
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
  struct inode_disk data; /* Inode content. */
};

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);

  if (pos < inode->data.length) {
    // Calculate the block index based on the position
    int block_index = pos / BLOCK_SECTOR_SIZE;

    if (block_index < 12) {
      // Direct blocks
      return inode->data.direct[block_index];
    } else {
      // Indirect and doubly indirect blocks
      block_index -= 12; // Adjust for the direct blocks

      if (block_index < INDIRECT_PTRS) {
        // Indirect block
        block_sector_t* indirect_block = malloc(BLOCK_SECTOR_SIZE);
        if (indirect_block != NULL) {
          cache_read(inode->data.indirect, indirect_block, BLOCK_SECTOR_SIZE, 0);
          block_sector_t result = indirect_block[block_index];
          free(indirect_block);
          return result;
        }
      } else {
        // Doubly indirect block
        block_index -= INDIRECT_PTRS;

        int indirect_index = block_index / INDIRECT_PTRS;
        int within_indirect_index = block_index % INDIRECT_PTRS;

        block_sector_t* doubly_indirect_block = malloc(BLOCK_SECTOR_SIZE);
        if (doubly_indirect_block != NULL) {
          cache_read(inode->data.double_indirect, doubly_indirect_block, BLOCK_SECTOR_SIZE, 0);

          block_sector_t indirect_block_sector = doubly_indirect_block[indirect_index];
          free(doubly_indirect_block);

          if (indirect_block_sector != -1) {
            block_sector_t* indirect_block = malloc(BLOCK_SECTOR_SIZE);
            if (indirect_block != NULL) {
              cache_read(indirect_block_sector, indirect_block, BLOCK_SECTOR_SIZE, 0);
              block_sector_t result = indirect_block[within_indirect_index];
              free(indirect_block);
              return result;
            }
          }
        }
      }
    }
  }

  return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

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
  // lock_acquire(&free_lock);
  struct inode_disk* disk_inode = NULL;
  static char zeros[BLOCK_SECTOR_SIZE];
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
    // disk_inode->indirect = calloc(1,BLOCK_SECTOR_SIZE);
    // disk_inode->double_indirect = calloc(1,BLOCK_SECTOR_SIZE);

    for (size_t i = 0; i < sectors; ++i) {
      block_sector_t new_sector;

      // Use the second argument to store the allocated block sector
      if (i < 12) {
        if (free_map_allocate(1, &disk_inode->direct[i])) {
          cache_write(disk_inode->direct[i], zeros, BLOCK_SECTOR_SIZE, 0);
          success = true;
        } else {
          free(disk_inode);
          return false;
        }

        // Direct block
        // disk_inode->direct[i] = new_sector;
      } else if (i < 12 + INDIRECT_PTRS) {
        if (free_map_allocate(1, &new_sector)) {
          // Indirect block
          if (disk_inode->indirect == 0) {
            // Allocate an indirect block if not allocated yet
            if (!free_map_allocate(1, &disk_inode->indirect)) {
              // Handle allocation failure
              free(disk_inode);
              // lock_release(&free_lock);
              return false;
            }
            cache_write(disk_inode->indirect, zeros, BLOCK_SECTOR_SIZE, 0);
          }

          // Read the indirect block from the cache
          // block_sector_t *indirect_block = malloc(INDIRECT_PTRS * sizeof(block_sector_t));
          // cache_read(*disk_inode->indirect, indirect_block, BLOCK_SECTOR_SIZE, 0);

          // // Update the indirect block
          // indirect_block[i - 12] = new_sector;

          // Write the indirect block back to the cache
          cache_write(disk_inode->indirect, &new_sector, 4, (i - 12) * 4);
          success = true;
        } else {
          free(disk_inode);
          return false;
        }
      } else {
        if (free_map_allocate(1, &new_sector)) {
          // Double indirect block
          if (disk_inode->double_indirect == 0) {
            // Allocate a double indirect block if not allocated yet
            if (!free_map_allocate(1, &disk_inode->double_indirect)) {
              // Handle allocation failure
              free(disk_inode);
              // lock_release(&free_lock);
              return false;
            }
            // Initialize the doubly indirect block with zeros
            cache_write(disk_inode->double_indirect, zeros, BLOCK_SECTOR_SIZE, 0);
          }

          int indirect_index = (i - 12 - INDIRECT_PTRS) / INDIRECT_PTRS;
          int within_indirect_index = (i - 12 - INDIRECT_PTRS) % INDIRECT_PTRS;

          // Read the doubly indirect block from the cache
          block_sector_t doubly_indirect_block[INDIRECT_PTRS];
          cache_read(disk_inode->double_indirect, doubly_indirect_block, BLOCK_SECTOR_SIZE, 0);

          // Indirect block within doubly indirect block
          if (doubly_indirect_block[indirect_index] == 0) {
            // Allocate an indirect block if not allocated yet
            if (!free_map_allocate(1, &doubly_indirect_block[indirect_index])) {
              // Handle allocation failure
              free(disk_inode);
              // lock_release(&free_lock);
              return false;
            }
            // Initialize the indirect block with zeros
            cache_write(doubly_indirect_block[indirect_index], zeros, BLOCK_SECTOR_SIZE, 0);
            // Write the updated doubly indirect block back to the cache
            cache_write(disk_inode->double_indirect, doubly_indirect_block, BLOCK_SECTOR_SIZE, 0);
          }

          // Read the indirect block from the cache
          block_sector_t indirect_block[INDIRECT_PTRS];
          cache_read(doubly_indirect_block[indirect_index], indirect_block, BLOCK_SECTOR_SIZE, 0);

          // Update the indirect block
          indirect_block[within_indirect_index] = new_sector;

          // Write the indirect block back to the cache
          cache_write(doubly_indirect_block[indirect_index], indirect_block, BLOCK_SECTOR_SIZE, 0);
          success = true;
        } else {
          free(disk_inode);
          return false;
        }
      }
    }

    // Write the inode to the cache
    cache_write(sector, disk_inode, BLOCK_SECTOR_SIZE, 0);

    free(disk_inode);
  }

  // lock_release(&free_lock);
  return true;
}

// bool inode_resize(block_sector_t sector, int sectors) {
//     for (size_t i = 0; i < sectors; ++i) {
//       block_sector_t new_sector;

//       // Use the second argument to store the allocated block sector
//       if (i < 12) {
//         if (free_map_allocate(1, &disk_inode->direct[i])) {
//           cache_write(disk_inode->direct[i], zeros, BLOCK_SECTOR_SIZE, 0);
//           success = true;
//         }
//         else {
//           free(disk_inode);
//           return false;
//         }

//         // Direct block
//         // disk_inode->direct[i] = new_sector;
//       } else if (i < 12 + INDIRECT_PTRS) {
//         if (free_map_allocate(1, &new_sector)) {
//           // Indirect block
//           if (disk_inode->indirect == 0) {
//             // Allocate an indirect block if not allocated yet
//             if (!free_map_allocate(1, &disk_inode->indirect)) {
//               // Handle allocation failure
//               free(disk_inode);
//               // lock_release(&free_lock);
//               return false;
//             }
//             cache_write(disk_inode->indirect, zeros, BLOCK_SECTOR_SIZE, 0);
//           }

//           // Read the indirect block from the cache
//           // block_sector_t *indirect_block = malloc(INDIRECT_PTRS * sizeof(block_sector_t));
//           // cache_read(*disk_inode->indirect, indirect_block, BLOCK_SECTOR_SIZE, 0);

//           // // Update the indirect block
//           // indirect_block[i - 12] = new_sector;

//           // Write the indirect block back to the cache
//           cache_write(disk_inode->indirect, &new_sector, 4, (i - 12) * 4);
//           success = true;
//         } else {
//           free(disk_inode);
//           return false;
//         }
//       }
//       else {
//         if (free_map_allocate(1, &new_sector)) {
//             // Double indirect block
//           if (disk_inode->double_indirect == 0) {
//                 // Allocate a double indirect block if not allocated yet
//                 if (!free_map_allocate(1, &disk_inode->double_indirect)) {
//                     // Handle allocation failure
//                     free(disk_inode);
//                     // lock_release(&free_lock);
//                     return false;
//                 }
//                 // Initialize the doubly indirect block with zeros
//                 cache_write(disk_inode->double_indirect, zeros, BLOCK_SECTOR_SIZE, 0);
//           }

//             int indirect_index = (i - 12 - INDIRECT_PTRS) / INDIRECT_PTRS;
//             int within_indirect_index = (i - 12 - INDIRECT_PTRS) % INDIRECT_PTRS;

//             // Read the doubly indirect block from the cache
//             block_sector_t doubly_indirect_block[INDIRECT_PTRS];
//             cache_read(disk_inode->double_indirect, doubly_indirect_block, BLOCK_SECTOR_SIZE, 0);

//             // Indirect block within doubly indirect block
//             if (doubly_indirect_block[indirect_index] == 0) {
//                 // Allocate an indirect block if not allocated yet
//                 if (!free_map_allocate(1, &doubly_indirect_block[indirect_index])) {
//                     // Handle allocation failure
//                     free(disk_inode);
//                     // lock_release(&free_lock);
//                     return false;
//                 }
//                 // Initialize the indirect block with zeros
//                 cache_write(doubly_indirect_block[indirect_index], zeros, BLOCK_SECTOR_SIZE, 0);
//                 // Write the updated doubly indirect block back to the cache
//                 cache_write(disk_inode->double_indirect, doubly_indirect_block, BLOCK_SECTOR_SIZE, 0);
//             }

//             // Read the indirect block from the cache
//             block_sector_t indirect_block[INDIRECT_PTRS];
//             cache_read(doubly_indirect_block[indirect_index], indirect_block, BLOCK_SECTOR_SIZE, 0);

//             // Update the indirect block
//             indirect_block[within_indirect_index] = new_sector;

//             // Write the indirect block back to the cache
//             cache_write(doubly_indirect_block[indirect_index], indirect_block, BLOCK_SECTOR_SIZE, 0);
//             success = true;
//         }
//         else {
//           free(disk_inode);
//           return false;
//         }
//       }

//     }
// }
/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
  struct list_elem* e;
  struct inode* inode;

  /* Check whether this inode is already open. */
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      inode_reopen(inode);
      return inode;
    }
  }

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front(&open_inodes, &inode->elem);
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
  if (inode != NULL)
    inode->open_cnt++;
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

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0) {
    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);

    /* Deallocate blocks if removed. */
    if (inode->removed) {
      // Deallocate direct blocks
      for (int i = 0; i < 12; ++i) {
        if (inode->data.direct[i] != -1) {
          free_map_release(inode->data.direct[i], 1);
        }
      }

      // Deallocate indirect blocks
      if (inode->data.indirect != -1) {
        block_sector_t indirect_block[INDIRECT_PTRS];
        cache_read(inode->data.indirect, indirect_block, BLOCK_SECTOR_SIZE, 0);

        for (int i = 0; i < INDIRECT_PTRS; ++i) {
          if (indirect_block[i] != -1) {
            free_map_release(indirect_block[i], 1);
          }
        }

        free_map_release(inode->data.indirect, 1);
      }

      // Deallocate doubly indirect blocks
      if (inode->data.double_indirect != -1) {
        block_sector_t doubly_indirect_block[INDIRECT_PTRS];
        cache_read(inode->data.double_indirect, doubly_indirect_block, BLOCK_SECTOR_SIZE, 0);

        for (int i = 0; i < INDIRECT_PTRS; ++i) {
          if (doubly_indirect_block[i] != -1) {
            block_sector_t indirect_block[INDIRECT_PTRS];
            cache_read(doubly_indirect_block[i], indirect_block, BLOCK_SECTOR_SIZE, 0);

            for (int j = 0; j < INDIRECT_PTRS; ++j) {
              if (indirect_block[j] != -1) {
                free_map_release(indirect_block[j], 1);
              }
            }

            free_map_release(doubly_indirect_block[i], 1);
          }
        }

        free_map_release(inode->data.double_indirect, 1);
      }

      free_map_release(inode->sector, 1);
    }

    free(inode);
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
  ASSERT(inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;

  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    // if ((int)sector_idx <0) {
    //   return 0;
    // }
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
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

  if (inode->deny_write_cnt)
    return 0;

  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    // if ((int)sector_idx <0) {
    //   return 0;
    // }
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
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
  inode->deny_write_cnt++;
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode* inode) { return inode->data.length; }

float get_buffer_accesses() { return cache_accesses; }

float get_buffer_hits() { return cache_hits; }

long get_device_writes() { return get_writes(fs_device); }