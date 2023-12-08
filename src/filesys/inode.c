#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"

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

/* Initializes the inode module. */
void inode_init(void) {
  list_init(&open_inodes);
  //lock_init(&inode_list_lock);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length) {
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
      block_write(fs_device, sector, disk_inode);
      if (sectors > 0) {
        static char zeros[BLOCK_SECTOR_SIZE];
        size_t i;

        for (i = 0; i < sectors; i++)
          block_write(fs_device, disk_inode->start + i, zeros);
      }
      success = true;
    }
    free(disk_inode);
  }
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
  // initialize ionde lock
  // lock_init(&inode->lock);
  //lock_acquire(&inode->lock);
  block_read(fs_device, inode->sector, &inode->data);
  //lock_release(&inode->lock);
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
  uint8_t* bounce = NULL;

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
      block_read(fs_device, sector_idx, buffer + bytes_read);
    } else {
      /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }
      block_read(fs_device, sector_idx, bounce);
      memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }
  free(bounce);

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
  uint8_t* bounce = NULL;

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
      block_write(fs_device, sector_idx, buffer + bytes_written);
    } else {
      /* We need a bounce buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }

      /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
      if (sector_ofs > 0 || chunk_size < sector_left)
        block_read(fs_device, sector_idx, bounce);
      else
        memset(bounce, 0, BLOCK_SECTOR_SIZE);
      memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
      block_write(fs_device, sector_idx, bounce);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }
  free(bounce);

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
off_t inode_length(const struct inode* inode) { return inode->data->length; }

/* Allocates a disk sector and returns its number. */
block_sector_t block_allocate() {
  block_sector_t next_sector;
  if (!free_map_allocate(1, &next_sector)) {
    return -1;
  }
  return next_sector;
}

/* Frees disk sector N*/
void block_free(block_sector_t n) { free_map_release(n, 1); }

/* Grows or shrinks the inode based on the given size. */
bool inode_resize(struct inode* inode, off_t size) {
  struct inode_disk* data = inode->data;

  /* Handle direct ptrs. */
  for (int i = 0; i < 12; i++) {
    if (size <= BLOCK_SECTOR_SIZE * i && data->direct[i] != 0) {
      /* Shrink. */
      block_free(data->direct[i]);
      data->direct[i] = 0;
    } else if (size > BLOCK_SECTOR_SIZE * i && data->direct[i] == 0) {
      /* Grow. */
      block_sector_t next = block_allocate();
      if (next == -1)
        return false;
      data->direct[i] = next;
    }
  }

  /* Check if indirect pointers are needed. */
  if (data->indirect == 0 && size <= 12 * BLOCK_SECTOR_SIZE) {
    data->length = size;
    return true;
  }
  block_sector_t buffer[128];
  memset(buffer, 0, 512);
  if (data->indirect == 0) {
    /* Allocate indirect block. */
    block_sector_t next = block_allocate();
    if (next == -1)
      return false;
    data->indirect = next;
  } else {
    /* Read in indirect block. */
    block_read(fs_device, data->indirect, buffer);
  }

  /* Handle indirect ptrs. */
  for (int i = 0; i < 128; i++) {
    if (size <= (12 + i) * BLOCK_SECTOR_SIZE && buffer[i] != 0) {
      /* Shrink. */
      block_free(buffer[i]);
      buffer[i] = 0;
    } else if (size > (12 + i) * BLOCK_SECTOR_SIZE && buffer[i] == 0) {
      /* Grow. */
      block_sector_t next = block_allocate();
      if (next == (block_sector_t)-1)
        return false;
      buffer[i] = next;
    }
  }
  if (size <= 12 * BLOCK_SECTOR_SIZE) {
    /* We shrank the inode such that indirect pointers are not required. */
    block_free(data->indirect);
    data->indirect = 0;
  } else {
    /* Write the updates to the indirect block back to disk. */
    block_write(fs_device, data->indirect, buffer);
  }
  // if (!handle_indirect_ptrs(data, size)) return false;

  /* Check if doubly indirect pointers are needed. */
  if (data->doubly_indirect == 0 && size <= 12 * BLOCK_SECTOR_SIZE + (128 * BLOCK_SECTOR_SIZE)) {
    data->length = size;
    return true;
  }
  memset(buffer, 0, 512);
  if (data->doubly_indirect == 0) {
    /* Allocate doubly indirect block. */
    block_sector_t next = block_allocate();
    if (next == -1)
      return false;
    data->doubly_indirect = next;
  } else {
    /* Read in indirect block. */
    block_read(fs_device, data->doubly_indirect, buffer);
  }

  /* Handle doubly indirect ptrs. */
  for (int i = 0; i < 128; i++) {
    if (size <= (12 + 128 + i) * BLOCK_SECTOR_SIZE && buffer[i] != 0) {
      /* Shrink. */
      block_free(buffer[i]);
      buffer[i] = 0;
    } else if (size > (12 + 128 + i) * BLOCK_SECTOR_SIZE && buffer[i] == 0) {
      /* Grow. */
      // Will need to read indirect block
      block_sector_t ind_buffer[128];
      memset(ind_buffer, 0, 512);
      for (int j = 0; j < 128; j++) {
        if (buffer[i] == 0) {
          /* Allocate indirect block. */
          block_sector_t next = block_allocate();
          if (next == -1)
            return false;
          buffer[i] = next;
        } else {
          /* Read in indirect block. */
          block_read(fs_device, buffer[i], ind_buffer);
        }
        // handle indirect ptrs within doubly indirect pointer
        for (int k = 0; k < 128; k++) {
          if (size <= (12 + 128 + j) * BLOCK_SECTOR_SIZE && ind_buffer[k] != 0) {
            /* Shrink. */
            block_free(ind_buffer[k]);
            ind_buffer[k] = 0;
          } else if (size > (12 + 128 + k) * BLOCK_SECTOR_SIZE && ind_buffer[k] == 0) {
            /* Grow. */
            block_sector_t next = block_allocate();
            if (next == -1)
              return false;
            ind_buffer[k] = next;
          }
        }
        if (size <= (12 + 128) * BLOCK_SECTOR_SIZE) {
          /* We shrank the inode such that indirect pointers are not required. */
          block_free(buffer[i]);
          buffer[i] = 0;
        } else {
          /* Write the updates to the indirect block back to disk. */
          block_write(fs_device, buffer[i], ind_buffer); // <-----
        }
      }
    }
  }
  if (size <=
      12 * BLOCK_SECTOR_SIZE + (128 * BLOCK_SECTOR_SIZE) + (128 * 128 * BLOCK_SECTOR_SIZE)) {
    /* We shrank the inode such that doubly indirect pointers are not required. */
    block_free(data->doubly_indirect);
    data->doubly_indirect = 0;
  } else {
    /* Write the updates to the indirect block back to disk. */
    block_write(fs_device, data->doubly_indirect, buffer);
  }

  data->length = size;
  return true;
}

// bool handle_indirect_ptrs(struct inode_disk* data, block_sector_t* id, off_t size){
//    /* Check if indirect pointers are needed. */
//   if (*id == 0 && size <= 12 * BLOCK_SECTOR_SIZE) {
//     data->length = size;
//     return true;
//   }
//   block_sector_t buffer[128];
//   memset(buffer, 0, 512);
//   if (*id == 0) {
//     /* Allocate indirect block. */
//     block_sector_t next = block_allocate();
//     if (next == -1) return false;
//     *id = next;
//   } else {
//     /* Read in indirect block. */
//     block_read(fs_device, *id, buffer);
//   }

//   /* Handle indirect ptrs. */
//   for (int i = 0; i < 128; i++) {
//     if (size <= (12 + i) * BLOCK_SECTOR_SIZE && buffer[i] != 0) {
//       /* Shrink. */
//       block_free(buffer[i]);
//       buffer[i] = 0;
//     } else if (size > (12 + i) * BLOCK_SECTOR_SIZE && buffer[i] == 0) {
//       /* Grow. */
//       block_sector_t next = block_allocate();
//       if (next == -1) return false;
//       buffer[i] = next;
//     }
//   }
//   if (size <= 12 * BLOCK_SECTOR_SIZE) {
//     /* We shrank the inode such that indirect pointers are not required. */
//     block_free(*id);
//     *id = 0;
//     } else {
//     /* Write the updates to the indirect block back to disk. */
//     block_write(fs_device, *id, buffer);
//   }
//   return true;
// }