#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

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
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
    process_exit();
  }

  if (args[0] == SYS_PRACTICE) {
    f->eax = args[1] + 1;
  }
  
  if(args[0] == SYS_WRITE){
    if(args[1] == 1){
      putbuf((void *) args[2], args[3]);
      f->eax = args[3];
    }
    else{
      //doesnt work
      f->eax = file_write(args[1], args[2],args[3]);
    }
  }
}

// static bool validate_pointer(void *ptr){
//  //need to validate pointer to read/write is also valid
//   //check if ptr is null
//   if(ptr == NULL){
//     return false;
//   }
//   //check if ptr is in kernal space
//   if(is_kernel_vaddr(ptr)){
//     return false;
//   }
//   //check if ptr is unmapped virtual memory
//   uint32_t* pd = active_pd();
//   if(lookup_page(pd, ptr, false) == NULL){
//     return false;
//   }  
//   return true;
// }
