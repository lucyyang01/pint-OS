#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }
bool validate_pointer(void* ptr);
void close(int fd);
int tell(int fd);
void seek(int fd, unsigned position);
int write(int fd, const void* buffer, unsigned size);
int read(int fd, void* buffer, unsigned size);
struct fileDescriptor find_fd(int fd_val);
int filesize(int fd);
int open(const char* file);
bool remove(const char* file);
bool create(const char* file, unsigned initialized_size);
static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  //printf("System call number: %d\n", args[0]);

  if (args[0] == SYS_EXIT) {
    f->eax = args[1];
    // printf("ARGS: %d\n", args[1]);
    // printf("Process NAME %s",thread_current()->pcb->process_name);
    //need to update status code
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
    //args[1] is const char *cmd_line
    //fork and exec
    // struct process* parent = thread_current()->pcb;
    // pid_t pid = get_pid(parent);
    //validate pointer is in user memory
    char* cmd_line = (char*)args[1];
    pid_t childpid = process_execute(cmd_line);
    if (childpid == TID_ERROR) {
      //go to parent process and update exit code
      thread_current()->pcb->exit_code = -1;
    } else {
      f->eax = childpid;
    }
    //up semaphore
    // sema_up(thread_current()->pcb->sema);
    // //down semaphore in parent
    // sema_down(thread_current()->pcb->sema);
    //free resources in case of failure
    //process_exit();
  }

  if (args[0] == SYS_WAIT) {
    pid_t child = args[1];
    //find child in list of children
    //down semaphore in child
    process_wait(child);
    //when done, store and return exit code from shared data
    //decrement ref count and destroy the data if failed
  }

  /*File SYS CALLS. All file syscalls must validate the arguments are above the stack and any buffers they point to.
    Create a new file descriptor if necessary using counter and validate.
  */

  if (args[0] == SYS_CREATE) {
    f->eax = create((char*)args[1], args[2]);
  }
  if (args[0] == SYS_REMOVE) {
    //remove file descriptor
    f->eax = remove(args[1]);
  }
  if (args[0] == SYS_OPEN) {
    f->eax = open(args[1]);
    //create new file descriptor elem
  }
  if (args[0] == SYS_CLOSE) {
    //remove file descriptor
    close(args[1]);
  }
  if (args[0] == SYS_FILESIZE) {
    f->eax = filesize(arg[1]);
  }
  if (args[0] == SYS_READ) {
    //file_read();
    f->eax = read(args[1]);
  }
  if (args[0] == SYS_WRITE) {
    f->eax = write(args[1], args[2], args[3]);
  }
  if (args[0] == SYS_SEEK) {
    //find file
    //modify the pos element of the file
  }
  if (args[0] == SYS_TELL) {
    //check file descriptor exists and return the byte number
  }
}
//GLOBAL FILE LOCK?

/*Closes file descriptor fd. If the operation is unsuccessful, it fails silently.*/
void close(int fd) {
  struct fileDescriptor close_fd = find_fd(fd);
  if (close_fd == NULL)
    return;
  //close file
  file_close(close_fd->file);
  //remove fd from fdt
  //struct list_elem* list_remove(struct list_elem*);
  lock_acquire(&thread_current()->pcb->fileDescriptorTable->lock);
  list_remove(&close_fd->elem);
  lock_release(&thread_current()->pcb->fileDescriptorTable->lock);
}

/*Returns the position of the next byte to be read or written in open file fd, expressed in bytes 
 from the beginning of the file. If the operation is unsuccessful, it can either exit with -1 or it can just fail silently.*/
int tell(int fd) {
  struct fileDescriptor tell_fd = find_fd(fd);
  if (tell_fd == NULL)
    return -1;
  return (int)file_tell(tell_fd->file);
}

/*Changes the next byte to be read or written in open file fd to position, in bytes from the beginning of the file. 
 If fd does not correspond to an entry in the file descriptor table, this function should do nothing.*/
void seek(int fd, unsigned position) {
  struct fileDescriptor seek_fd = find_fd(fd);
  if (seek_fd == NULL)
    return;
  file_seek(seek_fd->file);
}

/* Writes size bytes from buffer to the open file with file descriptor fd. 
Returns the number of bytes actually written, which may be less than size 
if some bytes could not be written. Returns -1 if fd does not correspond 
to an entry in the file descriptor table.*/
int write(int fd, const void* buffer, unsigned size) {
  if (!validate_pointer(buffer)) {
    return -1;
  }
  if (fd == 1) {
    int bytes_written = 0;
    if (size > 300) {
      for (int b = 300; b <= size; b += 300) {
        putbuf(buffer + bytes_written, b);
        bytes_written += 300;
      }
      if (bytes_written < size) {
        putbuf(buffer + bytes_written, size - bytes_written);
      }
    } else {
      putbuf(buffer, size);
    }
    return size;
  }
  struct fileDescriptor open_fd = find_fd(fd);
  if (open_fd == NULL) {
    return -1;
  }
  return file_write(open_fd->file, buffer, size);
}

/* Reads size bytes from the file open as fd into buffer. 
Returns the number of bytes actually read (0 at EOF), or -1 if failed. */
int read(int fd, void* buffer, unsigned size) {
  if (!validate_pointer(buffer)) {
    return -1;
  }
  //check that fd is in fdt
  //deny writes?
  struct fileDescriptor read_fd = find_fd(fd);
  if (read_fd == NULL)
    return -1;
  return (int)file_read(read_fd->file, buffer, size);
}

/* Returns the size, in bytes, of the open file with file descriptor fd. 
Returns -1 if fd does not correspond to an entry in the file descriptor table.*/
int filesize(int fd) {
  struct fileDescriptor open_fd = find_fd(fd);
  if (open_fd == NULL)
    return -1;
  return file_length(open_fd->file);
}

/* Check if process fdt contains the fd. Return fileDescriptor if found, NULL otherwise. */
struct fileDescriptor find_fd(int fd_val) {
  //check to see if fd is 0 or 1
  struct fileDescriptor_list* fdt = thread_current()->pcb->fileDescriptorTable;
  lock_acquire(fdt->lock);

  list_elem* el;
  for (el = list_begin(fdt->lst); el != list_end(fdt->lst); el = list_next(el)) {
    struct fileDescriptor* fileDescriptor_entry = list_entry(el, fdt->lst, elem);
    if (fileDescriptor_entry->fd == fd_val) {
      lock_release(fdt->lock);
      return fileDescriptor_entry->fd;
    }
  }
  return NULL;
}

/* Opens the file named file. Returns a nonnegative file descriptor
if successful, or -1 if the file couldn't be opened. */
int open(const char* file) {
  if (!validate_pointer(file)) {
    return -1;
  }
  //open file
  struct file* opened = filesys_open(file);
  if (opened == NULL) {
    return -1;
  }
  //add new file descriptor to fdt
  //TODO: deny writes if we open an executable?
  lock_acquire(&thread_current()->pcb->fileDescriptorTable->lock);
  fileDescriptor* new_entry = malloc(sizeof(fileDescriptor));
  int new_fd = thread_current()->pcb->fileDescriptorTable->fd;
  new_entry->fd = new_fd;
  new_entry->file = opened;
  list_push_back(&thread_current()->pcb->fileDescriptorTable->lst, &new_entry->elem);
  thread_current()->pcb->fdt_count += 1;
  lock_release(&thread_current()->pcb->fileDescriptorTable->lock);
  return new_fd;
}

/* Deletes the file named file. Returns true if successful, false otherwise. */
bool remove(const char* file) {
  if (!validate_pointer(file)) {
    return false;
  }
  return filesys_remove(file);
}

/* Creates a new file called file initially initial_size bytes in size. 
** Return True if successful, otherwise False */
bool create(const char* file, unsigned initialized_size) {
  if (!validate_pointer(file)) {
    return false;
  }
  return filesys_create(file, initialized_size);
}

bool validate_pointer(void* ptr) {
  //need to validate pointer to read/write is also valid
  //check if ptr is null
  if (ptr == NULL) {
    return false;
  }
  //check if ptr is in kernal space
  if (is_kernel_vaddr(ptr)) {
    return false;
  }
  //check if ptr is unmapped virtual memory
  // uint32_t* pd = active_pd();
  // if(lookup_page(pd, ptr, false) == NULL){
  //   return false;
  // }
  //also need to check if pointers to buffers are valid
  return true;
}
