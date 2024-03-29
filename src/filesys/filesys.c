#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/inode.h"
#include <stdbool.h>
#include "userprog/process.h"

/* Partition that contains the file system. */
struct block* fs_device;

static void do_format(void);
//bool filesys_create(const char* name, off_t initial_size, bool is_dir);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");

  inode_init();
  free_map_init();

  if (format)
    do_format();

  free_map_open();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) {

  free_map_close();
  cache_flush();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char* name, off_t initial_size, bool isdir) {
  block_sector_t inode_sector = 0;
  struct dir* dir;
  if (isdir) {
    char last_name[NAME_MAX + 1];
    char* base_path = get_base_path(name, last_name);
    dir = resolve_path(base_path);
    if (dir->inode->removed)
      return false;
    inode_sector = dir->inode->sector;
    name = last_name;
  } else {
    if (!thread_current()->pcb->cwd)
      dir = dir_open_root();
    else {
      dir = thread_current()->pcb->cwd;
      inode_sector = dir->inode->sector;
    }
    if (dir == NULL || dir_get_inode(dir)->removed)
      return false;
  }
  bool success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
                  inode_create(inode_sector, initial_size) && dir_add(dir, name, inode_sector));
  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  dir_close(dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file* filesys_open(const char* name) {
  struct dir* dir = dir_open_root();
  struct inode* inode = NULL;

  if (dir != NULL)
    dir_lookup(dir, name, &inode);
  dir_close(dir);

  return file_open(inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* name) {
  struct dir* dir = dir_open_root();
  bool success = dir != NULL && dir_remove(dir, name);
  dir_close(dir);

  return success;
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16))
    PANIC("root directory creation failed");
  // struct fileDescriptor_list* fdt = thread_current()->pcb->fileDescriptorTable;

  // lock_acquire(&(fdt->lock));
  // struct fileDescriptor* new_entry = malloc(sizeof(struct fileDescriptor));
  // int new_fd = fdt->fdt_count;
  // new_entry->fd = new_fd;
  // new_entry->file = NULL;
  // new_entry->is_dir = true;
  // new_entry->dir = dir_open_root();
  // list_push_back(&fdt->lst, &new_entry->elem);
  // fdt->fdt_count++;
  // lock_release(&fdt->lock);
  // struct dir* root_dir = dir_open_root();
  // struct inode* root_inode = dir_get_inode(root_dir);
  // if (!root_inode)
  //   printf("ROOT INODE IS NULL======");
  // root_inode->data.is_dir = true;
  // dir_close(root_dir);

  free_map_close();
  printf("done.\n");
}