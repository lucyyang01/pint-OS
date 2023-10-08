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
    filesys_remove(args[1]);
  }
  if (args[0] == SYS_OPEN) {
    filesys_open(args[1]);
    //create new file descriptor elem
  }
  if (args[0] == SYS_CLOSE) {
    //remove file descriptor
  }
  if (args[0] == SYS_FILESIZE) {
    //Grab file from file descriptor leng
    //file_length();
  }
  if (args[0] == SYS_READ) {
    //file_read();
  }
  if (args[0] == SYS_WRITE) {
    if (args[1] == 1) {
      putbuf((void*)args[2], args[3]);
      f->eax = args[3];
    } else {
      //doesnt work
      //need to get file from file descriptor arg
      f->eax = file_write(args[1], args[2], args[3]);
    }
  }
  if (args[0] == SYS_SEEK) {
    //find file
    //modify the pos element of the file
  }
  if (args[0] == SYS_TELL) {
    //check file descriptor exists and return the byte number
  }
}

/* Reads size bytes from the file open as fd into buffer. 
Returns the number of bytes actually read (0 at EOF), or -1 if failed. */
int read(int fd, void* buffer, unsigned size) {}

/* Returns the size, in bytes, of the open file with file descriptor fd. 
Returns -1 if fd does not correspond to an entry in the file descriptor table.*/
int filesize(int fd) {
  list* fdt = thread_current()->pcb->fileDescriptionTable;
  list_elem* el;
  for (el = list_begin(fdt); el != list_end(fdt); el = list_next(el)) {
    struct
  }
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
  //FDT only stores open files
  //create a new fileDescriptor_list_elem
  //word_count_t *new_word = malloc(sizeof(word_count_t));
  //list_push_back(&wclist->lst, &new_word->elem);
  fileDescriptor* new_entry = malloc(sizeof(fileDescriptor));
  int new_fd = thread_current()->pcb->fileDescriptorTable->fd;
  new_entry->fd = new_fd;
  new_entry->file = opened;
  list_push_back(&thread_current()->pcb->fileDescriptorTable, &new_entry->elem);
  //set the file field to the file returned by filesys_open
  //denywrite function
  thread_current()->pcb->fdt_count += 1;
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
