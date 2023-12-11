
#include <string.h>
#include "userprog/syscall.h"
#include "threads/malloc.h"
#include <stdbool.h>
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include <devices/shutdown.h>
#include <float.h>
#include "filesys/directory.h"
#include "filesys/inode.h"

static void syscall_handler(struct intr_frame* f UNUSED);
void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }
bool validate_pointer(void* ptr);
void close(int fd);
int tell(int fd);
void seek(int fd, unsigned position);
int write(int fd, const void* buffer, unsigned size);
int read(int fd, void* buffer, unsigned size);
struct fileDescriptor* find_fd(int fd_val);
int filesize(int fd);
int open(const char* file);
bool remove(const char* file);
bool create(const char* file, unsigned initialized_size);
double compute_e(int n);
double get_buffer_hitrate();
bool chdir(const char* dir);
bool mkdir(const char* dir);
bool readdir(int fd, char* name);
bool isdir(int fd);
struct dir* resolve_path(const char* path_name);
static int get_next_part(char part[NAME_MAX + 1], const char** srcp);
int inumber(int fd);
//char* get_base_path(char* path, char last_name[NAME_MAX + 1]);
char* get_base_path(char* path, char last_name[NAME_MAX + 1]);
static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  if (!validate_pointer(args)) {
    f->eax = -1;
    process_exit();
  }
  if (!validate_pointer(args + sizeof(args))) {
    f->eax = -1;
    process_exit();
  }

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  if (args[0] == SYS_EXIT) {
    f->eax = args[1];
    thread_current()->pcb->exit_code = args[1];
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
    process_exit();
  }

  if (args[0] == SYS_PRACTICE) {
    f->eax = args[1] + 1;
  }

  if (args[0] == SYS_HALT) {
    shutdown_power_off();
  }

  if (args[0] == SYS_EXEC) {
    if (!validate_pointer(args[1])) {
      f->eax = -1;
      process_exit();
    }
    const char* cmd_line = args[1];
    while (true) {
      // Check if the current character's address is valid
      if (!validate_pointer(cmd_line)) {
        f->eax = -1;
        process_exit();
      }

      // Exit loop if we've hit the end of the string
      if (*cmd_line == '\0') {
        break;
      }

      // Move to the next character
      cmd_line++;
    }

    //args[1] is const char *cmd_line
    //down semaphore
    //validate pointer is in user memory

    f->eax = process_execute(args[1]);
    //up semaphore
    //free resources in case of failure
  }

  if (args[0] == SYS_WAIT) {
    pid_t child = args[1];
    //find child in list of children
    //down semaphore in child
    f->eax = process_wait(child);
    //when done, store and return exit code from shared data
    //decrement ref count and destroy the data if failed
  }

  /*File SYS CALLS. All file syscalls must validate the arguments are above the stack and any buffers they point to.
    Create a new file descriptor if necessary using counter and validate.
  */

  if (args[0] == SYS_CREATE) {
    if (!validate_pointer(args[1])) {
      f->eax = -1;
      process_exit();
    }
    f->eax = create((char*)args[1], args[2]);
  }
  if (args[0] == SYS_REMOVE) {
    //remove file descriptor
    if (!validate_pointer(args[1])) {
      f->eax = -1;
      process_exit();
    }
    f->eax = remove((char*)args[1]);
  }
  if (args[0] == SYS_OPEN) {
    if (!validate_pointer(args[1])) {
      f->eax = -1;
      process_exit();
    }
    f->eax = open((char*)args[1]);
    //create new file descriptor elem
  }
  if (args[0] == SYS_CLOSE) {
    close(args[1]);
  }
  if (args[0] == SYS_FILESIZE) {
    f->eax = filesize(args[1]);
  }
  if (args[0] == SYS_READ) {
    if (!validate_pointer(args[2])) {
      f->eax = -1;
      process_exit();
    }
    f->eax = read(args[1], (char*)args[2], args[3]);
  }
  if (args[0] == SYS_WRITE) {

    if (!validate_pointer(args[2])) {
      f->eax = -1;
      process_exit();
    }
    f->eax = write(args[1], (char*)args[2], args[3]);
  }
  if (args[0] == SYS_SEEK) {
    seek(args[1], args[2]);
  }
  if (args[0] == SYS_TELL) {
    f->eax = tell(args[1]);
  }
  if (args[0] == SYS_COMPUTE_E) {
    f->eax = compute_e(args[1]);
  }
  if (args[0] == SYS_HITS) {
    f->eax = get_buffer_hits();
  }
  if (args[0] == SYS_ACCESSES) {
    f->eax = get_buffer_accesses();
  }
  if (args[0] == SYS_FLUSH) {
    cache_flush();
    //cache_flush();
  }
  if (args[0] == SYS_DEVICE_WRITES) {
    f->eax = get_device_writes();
  }

  /* DIRECTORY SYSCALLS, validate pointers?*/
  if (args[0] == SYS_CHDIR) {
    f->eax = chdir(args[1]);
  }
  if (args[0] == SYS_MKDIR) {
    f->eax = mkdir(args[1]);
  }
  if (args[0] == SYS_ISDIR) {
    f->eax = isdir(args[1]);
  }
  if (args[0] == SYS_INUMBER) {
    f->eax = inumber(args[1]);
  }
}

/*DIRECTORY SYSCALLS*/

/* Return inode number of inode associated with fd. */
int inumber(int fd) {
  struct fileDescriptor* file_desc = find_fd(fd);
  if (file_desc->is_dir)
    return inode_get_inumber(file_desc->dir->inode);
  return inode_get_inumber(file_desc->file->inode);
}

/* Change CWD of process to dir (relative or absolute). Returns true on success, false on failure.*/
bool chdir(const char* dir) {
  struct dir* new_cwd = resolve_path(dir); //new_cwd should have been opened in resolve_path
  if (new_cwd == NULL)
    return false;
  thread_current()->pcb->cwd = new_cwd;
  //printf("CHDIR SUCCEEDED=======");
  return true;
}

bool mkdir(const char* dir) {
  // //automatically make . and .. directories
  //printf("MADE IT HERE=========");
  if (strlen(dir) == 0)
    return false;
  char last_name[NAME_MAX + 1];
  // char copy_path[150];
  // strlcpy(copy_path, dir, strlen(dir) + 1);
  //printf("copy_path: %s\n", copy_path);
  char* base_path = get_base_path(dir, &last_name);
  //printf("last_name: %s\n", last_name);
  //printf("base path: %s\n", base_path);
  // struct dir* curr_dir;

  // a/b/c    base path: a/b/ last_name : c

  //if base path null search cwd
  struct dir* parent_dir;
  if (base_path == NULL) {
    //printf("MADE IT HERE");
    parent_dir = thread_current()->pcb->cwd;
    //if uninitialized, open root
    if (!parent_dir)
      parent_dir = dir_open_root();
  } else
    parent_dir = resolve_path(base_path);

  //allocate and create the new directory
  //block_sector_t* sectorp = malloc(sizeof(block_sector_t));
  block_sector_t sectorp;
  if (!free_map_allocate(1, &sectorp))
    return false;
  if (!dir_create(sectorp, 16))
    return false;

  //create a dir struct
  struct dir* new_dir = malloc(sizeof(dir));
  new_dir->parent = parent_dir;
  new_dir->inode = inode_open(sectorp);
  new_dir->pos = 0;
  new_dir->inode->data.is_dir = true;

  //add a fdt entry for this directory
  struct fileDescriptor_list* fdt = thread_current()->pcb->fileDescriptorTable;
  lock_acquire(&(fdt->lock));
  struct fileDescriptor* new_entry = malloc(sizeof(struct fileDescriptor));
  int new_fd = fdt->fdt_count;
  new_entry->fd = new_fd;
  new_entry->file = NULL;
  new_entry->is_dir = true;
  new_entry->dir = new_dir;
  list_push_back(&fdt->lst, &new_entry->elem);
  fdt->fdt_count++;
  lock_release(&fdt->lock);
  //add new dir entry to parent dir
  // if (parent_dir == NULL)
  //mkdir 3 -> /3
  //create 3 -> 3
  // char name[] = "/";
  // strlcat(name, last_name, sizeof(last_name) + 1);

  //0/2/0 mkdir create 3:

  if (!dir_add(parent_dir, last_name, new_dir->inode->sector))
    return false;

  return true;
}

//this function is treated like an iterator
bool readdir(int fd, char* name) {
  struct fileDescriptor* file_desc = find_fd(fd);
  if (!file_desc->is_dir)
    return false;
  return dir_readdir(file_desc->dir, name);
}

/* Returns true if fd corresponds to a directory, false if ordinary file. */
bool isdir(int fd) {
  struct fileDescriptor* file_desc = find_fd(fd);
  return file_desc->is_dir;
}

/* Returns the base*/
char* get_base_path(char* path, char last_name[NAME_MAX + 1]) {
  //char last_name[NAME_MAX + 1];
  char copy_path[150];
  strlcpy(copy_path, path, strlen(path) + 1);
  //printf("copy_path: %s\n", copy_path);
  int og_length = strlen(path);
  int count = 0;
  char* srcp = path;
  //char* dst;
  //get_next_part(last_name, &srcp);
  // printf("oglength: %d\n", og_length);
  while (get_next_part(last_name, &srcp) == 1) {
    count += 1;
  }
  //last_name contains the file name
  //if the file name is the whole path, we search in cwd
  if (strcmp(last_name, copy_path) == 0)
    return NULL;
  //printf("len last name %d\n", strlen(last_name));
  int truncate = (og_length)-strlen(last_name);
  //printf("last_name: %s\n", last_name);
  // printf("truncate: %d\n", truncate);
  //printf("copy path: %s\n", copy_path);
  copy_path[truncate] = '\0';
  //printf("cpy path after truncate: %s\n", copy_path);
  char* dst = (char*)malloc(strlen(copy_path) + 1);
  strlcpy(dst, copy_path, strlen(copy_path) + 1);
  //printf("dst: %s\n", dst);
  return dst;
}

/* Helper function to resolve paths by traversing via dir_lookup*/
struct dir* resolve_path(const char* path_name) { //path_name is the path the user passed in
  struct dir* curr_dir;
  if (path_name[0] == '/' || thread_current()->pcb->cwd == NULL) {
    curr_dir = dir_open_root(); // /home/user: what if home is the root dir
  } else {
    curr_dir = thread_current()->pcb->cwd;
  }
  char name_part[NAME_MAX + 1];
  // strlcpy(dup_path, *path_name, strlen(path_name) + 1);
  //char* dup_path = strdup(path_name);
  char* srcp = path_name;
  while (get_next_part(name_part, &srcp) == 1 && curr_dir) {
    struct inode* inode;
    //printf("name_part: %s\n", name_part);
    if (dir_lookup(curr_dir, name_part, &inode)) {
      //printf("DIR_LOOKUP FOUND THE DIR");
      dir_close(curr_dir);
      curr_dir = dir_open(inode);
      //memset(name_part, 0, sizeof name_part);
    } else {
      //printf("DIR_LOOKUP RETURNED FALSE");
      curr_dir = NULL;
    }
  }
  //printf("MADE IT TO RESOLVE PATH");
  //if successful, curr_dir should contain the dir we want
  return curr_dir;
}

/* Extracts a file name part from *SRCP into PART, and updates *SRCP so that the
   next call will return the next file name part. Returns 1 if successful, 0 at
   end of string, -1 for a too-long file name part. */
static int get_next_part(char part[NAME_MAX + 1], const char** srcp) {
  const char* src = *srcp;
  char* dst = part;

  /* Skip leading slashes.  If it's all slashes, we're done. */
  while (*src == '/')
    src++;
  if (*src == '\0')
    return 0;

  /* Copy up to NAME_MAX character from SRC to DST.  Add null terminator. */
  while (*src != '/' && *src != '\0') {
    if (dst < part + NAME_MAX)
      *dst++ = *src;
    else
      return -1;
    src++;
  }
  *dst = '\0';

  /* Advance source pointer. */
  *srcp = src;

  return 1;
}

/* FILE SYSCALLS*/

double compute_e(int n) { return (double)sys_sum_to_e(n); }

/*Closes file descriptor fd. If the operation is unsuccessful, it fails silently.*/
void close(int fd) {
  struct fileDescriptor* close_fd = find_fd(fd);
  if (close_fd == NULL)
    return;
  //if directory, just close it
  if (close_fd->is_dir)
    dir_close(close_fd->dir);
  else {
    //close file
    file_close(close_fd->file);
    //remove fd from fdt
    lock_acquire(&thread_current()->pcb->fileDescriptorTable->lock);
    list_remove(&close_fd->elem);
    lock_release(&thread_current()->pcb->fileDescriptorTable->lock);
  }
}

/*Returns the position of the next byte to be read or written in open file fd, expressed in bytes 
 from the beginning of the file. If the operation is unsuccessful, it can either exit with -1 or it can just fail silently.*/
int tell(int fd) {
  struct fileDescriptor* tell_fd = find_fd(fd);
  if (tell_fd == NULL)
    return -1;
  return (int)file_tell(tell_fd->file);
}

/*Changes the next byte to be read or written in open file fd to position, in bytes from the beginning of the file. 
 If fd does not correspond to an entry in the file descriptor table, this function should do nothing.*/
void seek(int fd, unsigned position) {
  struct fileDescriptor* seek_fd = find_fd(fd);
  if (seek_fd == NULL)
    return;
  file_seek(seek_fd->file, position);
}

/* Writes size bytes from buffer to the open file with file descriptor fd. 
Returns the number of bytes actually written, which may be less than size 
if some bytes could not be written. Returns -1 if fd does not correspond 
to an entry in the file descriptor table.*/
int write(int fd, const void* buffer, unsigned size) {
  if (fd == 1) {
    int bytes_written = 0;
    if (size > 300) {
      for (int b = 300; b <= (int)size; b += 300) {
        putbuf(buffer + bytes_written, b);
        bytes_written += 300;
      }
      if (bytes_written < (int)size) {
        putbuf(buffer + bytes_written, (int)size - bytes_written);
      }
    } else {
      putbuf(buffer, size);
    }
    return size;
  }
  struct fileDescriptor* open_fd = find_fd(fd);
  //fail if open_fd corresponds to a directory
  if (open_fd == NULL || open_fd->is_dir) {
    return -1;
  }
  return file_write(open_fd->file, buffer, size);
}

/* Reads size bytes from the file open as fd into buffer. 
Returns the number of bytes actually read (0 at EOF), or -1 if failed. */
int read(int fd, void* buffer, unsigned size) {
  struct fileDescriptor* read_fd = find_fd(fd);
  //fail if read_fd corresponds to a directory
  if (read_fd == NULL || read_fd->is_dir)
    return -1;
  return (int)file_read(read_fd->file, buffer, size);
}

/* Returns the size, in bytes, of the open file with file descriptor fd. 
Returns -1 if fd does not correspond to an entry in the file descriptor table.*/
int filesize(int fd) {
  struct fileDescriptor* open_fd = find_fd(fd);
  if (open_fd == NULL)
    return -1;
  return (int)file_length(open_fd->file);
}

/* Opens the file named file. Returns a nonnegative file descriptor
if successful, or -1 if the file couldn't be opened. */
int open(const char* file) { //cwd : a, file: "b" a/b
  if (strlen(file) == 0)
    return -1;
  struct file* opened = filesys_open(file);
  if (opened == NULL || opened->inode->data.is_dir) {
    char last_name[NAME_MAX + 1];
    char* base_path = get_base_path(file, last_name); // a/b/c base_path: a/b/ last_name: c
    struct dir* dir;
    ///////c base c: last : c
    //TODO: special behavior for root if fdt iteration doesn't work
    //struct dir* test_dir = resolve_path()

    //0/2/0/
    struct dir* base_dir = NULL;
    if (base_path != NULL)
      base_dir = resolve_path(base_path); //can't find directory b inside a
    if (base_path == NULL || base_dir) {  //base dir exists
      //0/2/0 last_name: c
      if (base_dir != NULL)
        dir = base_dir;
      else if (!thread_current()->pcb->cwd)
        dir = dir_open_root();
      else
        dir = thread_current()->pcb->cwd;
      //look for the file in dir
      struct inode* inode;
      //0/2/0/3 //3
      if (dir_lookup(dir, last_name, &inode) && !inode->data.is_dir) {
        //file_open(inode);
        struct fileDescriptor_list* fdt = thread_current()->pcb->fileDescriptorTable;
        lock_acquire(&(fdt->lock));
        struct fileDescriptor* new_entry = malloc(sizeof(struct fileDescriptor));
        int new_fd = fdt->fdt_count;
        new_entry->fd = new_fd;
        new_entry->file = opened;
        new_entry->is_dir = false;
        new_entry->dir = NULL;
        list_push_back(&fdt->lst, &new_entry->elem);
        fdt->fdt_count++;
        lock_release(&fdt->lock);
        return new_fd;
      }
    }
    dir = resolve_path(file);
    if (dir == NULL)
      //look for the file inside
      return -1;
    //printf("MADE IT HERE======");
    struct inode* inode = dir_get_inode(dir);
    if (inode->data.is_dir) {
      //find the fd corresponding to the directory
      int fd_from_dir = -1;
      struct fileDescriptor_list* fdt = thread_current()->pcb->fileDescriptorTable;
      lock_acquire(&fdt->lock);
      struct list_elem* el;
      for (el = list_begin(&fdt->lst); el != list_end(&fdt->lst); el = list_next(el)) {
        struct fileDescriptor* fileDescriptor_entry = list_entry(el, struct fileDescriptor, elem);
        if (dir_get_inode(fileDescriptor_entry->dir) == dir_get_inode(dir)) {
          fd_from_dir = fileDescriptor_entry->fd;
          //lock_release(&fdt->lock);
        }
      }
      lock_release(&fdt->lock);
      file_open(inode);
      return fd_from_dir;
    } else
      return -1;
  }
  //if opening a directory, resolve the
  struct fileDescriptor_list* fdt = thread_current()->pcb->fileDescriptorTable;
  lock_acquire(&(fdt->lock));
  struct fileDescriptor* new_entry = malloc(sizeof(struct fileDescriptor));
  int new_fd = fdt->fdt_count;
  new_entry->fd = new_fd;
  new_entry->file = opened;
  new_entry->is_dir = false;
  new_entry->dir = NULL;
  list_push_back(&fdt->lst, &new_entry->elem);
  fdt->fdt_count++;
  lock_release(&fdt->lock);
  return new_fd;

  //opening the root directory

  //TODO: how to tell if we want to open a dir or a file?
  // struct fileDescriptor_list* fdt = thread_current()->pcb->fileDescriptorTable;
  // struct dir* dir;
  // struct file* result;
  // if (!strcmp(file, "/")) {
  //   dir = dir_open_root();
  //   result = file_open(dir_get_inode(dir));
  //   //close root
  //   dir_close(dir);
  //   return result; //TODO: where do i add the fdt entry for the root directory?
  // }

  // char last_name[NAME_MAX + 1];
  // char* base_path = get_base_path(file, last_name);
  // // printf("last_name: %s\n", last_name);
  // // printf("base_path: %s\n", base_path);

  // if (base_path == NULL ) { //the path is just the name of the file, so search in cwd
  //   if (!thread_current()->pcb->cwd)
  //     dir = dir_open_root();
  //     //result = filesys_open(file)
  //   else
  //     dir = resolve_path(base_path);
  // struct inode* inode = dir_get_inode(dir);
  // if (inode->data.is_dir) {
  //   //find the fd corresponding to the directory
  //   int fd_from_dir;
  //   lock_acquire(&fdt->lock);
  //   struct list_elem* el;
  //   for (el = list_begin(&fdt->lst); el != list_end(&fdt->lst); el = list_next(el)) {
  //     struct fileDescriptor* fileDescriptor_entry = list_entry(el, struct fileDescriptor, elem);
  //     if (fileDescriptor_entry->dir == dir) {
  //       fd_from_dir = fileDescriptor_entry->fd;
  //       lock_release(&fdt->lock);
  //     }
  //   }
  //   lock_release(&fdt->lock);
  //   //open the directory
  //   file_open(inode);
  //   return fd_from_dir;
  // } else {
  //   struct file* opened = filesys_open(file);
  //   if (opened == NULL) {
  //     return -1;
  //   }
  //   //if opening a directory, resolve the
  //   lock_acquire(&(fdt->lock));
  //   struct fileDescriptor* new_entry = malloc(sizeof(struct fileDescriptor));
  //   int new_fd = fdt->fdt_count;
  //   new_entry->fd = new_fd;
  //   new_entry->file = opened;
  //   new_entry->is_dir = false;
  //   new_entry->dir = NULL;
  //   list_push_back(&fdt->lst, &new_entry->elem);
  //   fdt->fdt_count++;
  //   lock_release(&fdt->lock);
  //   return new_fd;
  // }
  //   //open the file

  // //   if (result == NULL)
  // //     return -1;
  // //   return result;
  // // }
  // //printf("file: %s\n", file);
  // //open file (we've changed to the file's parent directory)
  // //printf("REACHED OPEN======");
  // }
}

/* Deletes the file named file. Returns true if successful, false otherwise. */
bool remove(const char* file) {
  bool success = false;
  bool is_empty = true;
  //either the file doesn't exist or it's a directory
  //path resolve here before calling filesys remove?
  if (!filesys_remove(file)) {
    //figure out if a directory is empty
    struct dir* curr_dir = resolve_path(file);
    char name[NAME_MAX + 1];
    while (dir_readdir(curr_dir, &name)) {
      if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
        return false;
      }
    }
    char last_name[NAME_MAX + 1];
    char* base_path = get_base_path(file, last_name);
    dir_remove(curr_dir->parent, last_name);
  }
  return true;
}

/* Creates a new file called file initially initial_size bytes in size. 
** Return True if successful, otherwise False */
bool create(const char* file, unsigned initialized_size) {
  if (strlen(file) > NAME_MAX + 1)
    return false;
  char last_name[NAME_MAX + 1];
  // printf("file: %s\n", file);
  char* base_path = get_base_path(file, last_name);
  //struct dir* dir = resolve_path(base_path);
  bool is_dir = true;
  if (base_path == NULL || !strcmp(base_path, "/"))
    is_dir = false;
  // printf("WEFHWIFEHlast_name: %s\n", last_name);
  // printf("base_path: %s\n", base_path);
  return filesys_create(file, initialized_size, is_dir);
}

/* Check if process fdt contains the fd. Return fileDescriptor if found, NULL otherwise. */
struct fileDescriptor* find_fd(int fd_val) {
  //check to see if fd is 0 or 1
  struct fileDescriptor_list* fdt = thread_current()->pcb->fileDescriptorTable;
  lock_acquire(&fdt->lock);

  struct list_elem* el;
  for (el = list_begin(&fdt->lst); el != list_end(&fdt->lst); el = list_next(el)) {
    struct fileDescriptor* fileDescriptor_entry = list_entry(el, struct fileDescriptor, elem);
    if (fileDescriptor_entry->fd == fd_val) {
      lock_release(&fdt->lock);
      return fileDescriptor_entry;
    }
  }
  lock_release(&fdt->lock);
  return NULL;
}

//printf("MADE IT HERE");

//printf("MADE IT HERE");
//add . and .. to new dir
//free(sectorp);
//printf("MADE IT HERE");

/*THIS CODE IS FOR ADDING . AND .. TO THE NEW DIRECTORY*/

// if (dir_add(new_dir, ".", new_dir->inode->sector) && dir_add(new_dir, "..", new_dir->inode->sector)) {
//   //printf("MADE IT HERE");
//   return true;
// }
// if (!dir_add(new_dir, ".", new_dir->inode->sector)) {
//   printf("MADE IT HERE 1");
//   return false;
// }
// if (!dir_add(new_dir, "..", new_dir->inode->sector)) {
//   printf("MADE IT HERE 2");
//   return false;
// }
//printf("MADE IT HERE");