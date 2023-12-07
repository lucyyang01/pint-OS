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
    f->eax = cache_flush();
  }
}

double compute_e(int n) { return (double)sys_sum_to_e(n); }

/*Closes file descriptor fd. If the operation is unsuccessful, it fails silently.*/
void close(int fd) {
  struct fileDescriptor* close_fd = find_fd(fd);
  if (close_fd == NULL)
    return;
  //close file
  file_close(close_fd->file);
  //remove fd from fdt
  lock_acquire(&thread_current()->pcb->fileDescriptorTable->lock);
  list_remove(&close_fd->elem);
  lock_release(&thread_current()->pcb->fileDescriptorTable->lock);
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
  if (open_fd == NULL) {
    return -1;
  }
  return file_write(open_fd->file, buffer, size);
}

/* Reads size bytes from the file open as fd into buffer. 
Returns the number of bytes actually read (0 at EOF), or -1 if failed. */
int read(int fd, void* buffer, unsigned size) {
  struct fileDescriptor* read_fd = find_fd(fd);
  if (read_fd == NULL)
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
int open(const char* file) {
  //open file
  struct file* opened = filesys_open(file);
  if (opened == NULL) {
    return -1;
  }
  struct fileDescriptor_list* fdt = thread_current()->pcb->fileDescriptorTable;
  lock_acquire(&(fdt->lock));
  struct fileDescriptor* new_entry = malloc(sizeof(struct fileDescriptor));
  int new_fd = fdt->fdt_count;
  new_entry->fd = new_fd;
  new_entry->file = opened;
  list_push_back(&fdt->lst, &new_entry->elem);
  fdt->fdt_count++;
  lock_release(&fdt->lock);
  return new_fd;
}

/* Deletes the file named file. Returns true if successful, false otherwise. */
bool remove(const char* file) { return filesys_remove(file); }

/* Creates a new file called file initially initial_size bytes in size. 
** Return True if successful, otherwise False */
bool create(const char* file, unsigned initialized_size) {
  return filesys_create(file, initialized_size);
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