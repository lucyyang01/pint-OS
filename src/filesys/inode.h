#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include <list.h>
#include "filesys/off_t.h"
#include "devices/block.h"
#include <list.h>
#include "threads/synch.h"

struct bitmap;

struct buffer_cache_elem {
  block_sector_t sector;
  void* buffer[BLOCK_SECTOR_SIZE];
  struct lock block_lock;
  bool dirty;
  bool valid;
  struct list_elem elem;
};

void cache_flush();
void inode_init(void);
bool inode_create(block_sector_t, off_t);
struct inode* inode_open(block_sector_t);
struct inode* inode_reopen(struct inode*);
block_sector_t inode_get_inumber(const struct inode*);
void inode_close(struct inode*);
void inode_remove(struct inode*);
off_t inode_read_at(struct inode*, void*, off_t size, off_t offset);
off_t inode_write_at(struct inode*, const void*, off_t size, off_t offset);
void inode_deny_write(struct inode*);
void inode_allow_write(struct inode*);
off_t inode_length(const struct inode*);
block_sector_t block_allocate(void);
void block_free(block_sector_t);
bool inode_resize(struct inode*, off_t size);

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  block_sector_t start;           /* First data sector. */
  off_t length;                   /* File size in bytes. */
  unsigned magic;                 /* Magic number. */
  block_sector_t direct[12];      /* Direct pointers */
  block_sector_t indirect;        /* Inirect pointer */
  block_sector_t doubly_indirect; /* Doubly indirect pointer */
  // struct list* sector_locks_ptr; /* A pointer to a list or locks for each block sector */
  uint32_t unused[111]; /* Not used. */
  //bool is_dir;          /* If inode corresponds to file or directory.*/
};

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */

/* In-memory inode. */
struct inode {
  struct list_elem elem;   /* Element in inode list. */
  block_sector_t sector;   /* Sector number of disk location. */
  int open_cnt;            /* Number of openers. */
  bool removed;            /* True if deleted, false otherwise. */
  int deny_write_cnt;      /* 0: writes ok, >0: deny writes. */
  struct inode_disk* data; /* Pointer for Inode content. */
  struct lock lock;        /* Lock used for synchronizing access to inode metadata. */
  // bool is_dir;            /* Identifies if this is a directory. */
};

#endif /* filesys/inode.h */
