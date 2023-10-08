#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

static void syscall_handler(struct intr_frame*);
static bool validate_pointer(void* ptr);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  if (!validate_pointer(args)) {
    f->eax = -1;
    process_exit();
  }
  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  //printf("System call number: %d\n", args[0]);

  if (args[0] == SYS_EXIT) {
    f->eax = args[1];
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
    // if (!validate_pointer(&args)) {
    //   f->eax = -1;
    //   process_exit();
    // }
    if (!validate_pointer(&args[1])) {
      f->eax = -1;
      process_exit();
    }
    const char* cmd_line = &args[1];
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
    process_wait(child);
    //when done, store and return exit code from shared data
    //decrement ref count and destroy the data if failed
  }

  /*File SYS CALLS. All file syscalls must validate the arguments are above the stack and any buffers they point to.
    Create a new file descriptor if necessary using counter and validate.
  */

  if (args[0] == SYS_CREATE) {
    filesys_create(args[1], args[2]);
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
    //file_length();
  }

  if (args[0] == SYS_WRITE) {
    if (args[1] == 1) {
      //TODO: Check if you can write x amount of bytes here in memory
      // uint32_t  = f->esp + args[3] + 1;
      putbuf((void*)args[2], args[3]);
      if (!validate_pointer(args[0])) {
        f->eax = -1;
        process_exit();
      }
      f->eax = args[3];
    } else {
      //doesnt work
      //need to get file from file descriptor arg
      f->eax = file_write(args[1], args[2], args[3]);
    }
  }
}

static bool validate_pointer(void* ptr) {
  //need to validate pointer to read/write is also valid
  //check if ptr is null
  if (ptr == NULL) {
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, -1);
    return false;
  }
  //check if ptr is in kernal space
  if (is_kernel_vaddr(ptr)) {
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, -1);
    return false;
  }
  //check if ptr is unmapped virtual memory
  uint32_t* pd = active_pd();
  void* dog = pagedir_get_page(pd, ptr);
  if (dog == NULL) {
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, -1);
    return false;
  }
  return true;
}
