#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

// #include "lib/user/pthread.h"

char* strdup(const char* str);
static struct semaphore temporary;
static thread_func start_process NO_RETURN;
static thread_func start_pthread NO_RETURN;

static bool load(const char* file_name, void (**eip)(void), void** esp);
bool setup_thread(void (**eip)(void), void** esp, struct user_thread_input* input);
void push_to_stack(size_t argc, char* argv[], struct intr_frame* if_);
void init_file_descriptor_list(struct fileDescriptor_list* fdt);

/* Initialize a file descriptor list. */
void init_file_descriptor_list(struct fileDescriptor_list* fdt) {
  list_init(&(fdt->lst));
  lock_init(&(fdt->lock));
  fdt->fdt_count = 3;
}

/* Initializes user programs in the system by ensuring the main
   thread has a minimal PCB so that it can execute and wait for
   the first user process. Any additions to the PCB should be also
   initialized here if main needs those members */
void userprog_init(void) {
  struct thread* t = thread_current();
  bool success;

  /* Allocate process control block
     It is imoprtant that this is a call to calloc and not malloc,
     so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
     page directory) when t->pcb is assigned, because a timer interrupt
     can come at any time and activate our pagedir */
  t->pcb = calloc(sizeof(struct process), 1);

  /* Initialize pagedir and process_name to be null */
  success = t->pcb != NULL;
  t->pcb->main_thread = t;

  /* Initialize PCB's exec semaphore*/
  struct semaphore semaphore_exec;
  t->pcb->sema_exec = semaphore_exec;
  sema_init(&t->pcb->sema_exec, 0);

  /* Initialize PCB's wait semaphore*/
  struct semaphore semaphore_wait;
  t->pcb->sema_wait = semaphore_wait;
  sema_init(&t->pcb->sema_wait, 0);

  /* Initialize lock */
  lock_init(&(t->pcb->sherlock));

  /* Child Processes */

  list_init(&t->pcb->children);
  list_init(&t->pcb->user_thread_list);

  /* Reference Count*/
  t->pcb->ref_count = 2;

  t->pcb->pid = t->tid;

  t->pcb->exit_code = -1;

  /* Kill the kernel if we did not succeed */
  ASSERT(success);
}

/* Push arguments to Stack. */
void push_to_stack(size_t argc, char* argv[], struct intr_frame* if_) {
  //start at stack_ptr
  //push the address of each string plus a null pointer sentinel, on the stack, in right-to-left order
  char* argAddress[argc + 1];

  for (int i = argc - 1; i >= 0; i--) {
    if_->esp = if_->esp - strlen(argv[i]) - 1;
    argAddress[i] = if_->esp;

    memcpy(if_->esp, argv[i], strlen(argv[i]) + 1);
    free(argv[i]);
  }

  /* Calculate total size that will be pushed after alignment. */
  int total_size_to_push = (argc + 1) * sizeof(char*) /* argv addresses and null sentinel */
                           + sizeof(char**)           /* address of argv */
                           + sizeof(size_t);          /* argc */

  /* Adjust esp to ensure it will be 16-byte aligned after all pushes. */
  while ((uintptr_t)(if_->esp - total_size_to_push) % 16 != 0) {
    if_->esp = (char*)if_->esp - 1;
  }
  //add null ptr
  if_->esp = if_->esp - 4;
  *(uint32_t*)if_->esp = 0; // Push NULL onto the stack.

  //Then, push argv (the address of argv[0]) and argc, in that order. Finally, push a fake “return address”;

  /* Push the arguments onto the stack. */
  for (int i = argc - 1; i >= 0; i--) {
    if_->esp = if_->esp - sizeof(char*);
    *(char**)(if_->esp) = argAddress[i];
  }
  // Push argv[0]
  char** argv_ptr = (char**)if_->esp;
  if_->esp = if_->esp - 4;
  *(char***)(if_->esp) = argv_ptr;

  // Push argc
  if_->esp = if_->esp - 4;
  *((size_t*)if_->esp) = argc;

  //Push rip
  if_->esp = if_->esp - 4;

  *((size_t*)if_->esp) = 0;
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   process id, or TID_ERROR if the thread cannot be created. */
pid_t process_execute(const char* file_name) {
  char* fn_copy;
  tid_t tid;
  struct process_input* input = malloc(sizeof(struct process_input));

  sema_init(&temporary, 0);

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy(fn_copy, file_name, PGSIZE);

  input->parent = thread_current()->pcb;
  input->file_name = fn_copy;
  input->success = false;

  /* Save FPU of current thread. */

  /* If the file name is empty, exit process */
  if (strlen(file_name) == 0) {
    return TID_ERROR;
  }

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(file_name, PRI_DEFAULT, start_process, input);
  sema_down(&thread_current()->pcb->sema_exec);
  if (tid == TID_ERROR) {
    palloc_free_page(fn_copy);
  }

  if (!input->success) {
    return TID_ERROR;
  }
  if (input->success) {
    free(input);
  }
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void* i) {
  struct process_input* input = (struct process_input*)i;
  char* file_name = input->file_name;
  struct thread* t = thread_current();
  struct intr_frame if_;
  bool success, pcb_success;

  /* Allocate process control block */
  struct process* new_pcb = malloc(sizeof(struct process));
  success = pcb_success = new_pcb != NULL;

  /* Initialize process control block */
  if (success) {
    // Ensure that timer_interrupt() -> schedule() -> process_activate()
    // does not try to activate our uninitialized pagedir
    new_pcb->pagedir = NULL;
    t->pcb = new_pcb;
    // Continue initializing the PCB as normal
    t->pcb->main_thread = t;

    /* Initialize PCB's semaphore*/
    struct semaphore my_semaphore;
    t->pcb->sema_exec = my_semaphore;
    sema_init(&t->pcb->sema_exec, 0);

    /* Initialize PCB's wait semaphore*/
    struct semaphore semaphore_wait;
    t->pcb->sema_wait = semaphore_wait;
    sema_init(&t->pcb->sema_wait, 0);

    /* Initialize lock */
    lock_init(&(t->pcb->sherlock));

    /* Parent Process */
    t->pcb->parent = input->parent;

    /* Child Processes */
    list_init(&t->pcb->children);
    list_init(&t->pcb->user_thread_list);

    /* Reference Count*/
    t->pcb->ref_count = 2;

    /* PID of process */
    t->pcb->pid = t->tid;

    t->pcb->exit_code = -1;
    /* File Descriptor Table */
    struct fileDescriptor_list* fdt = malloc(sizeof(struct fileDescriptor_list));
    init_file_descriptor_list(fdt);

    t->pcb->fileDescriptorTable = fdt;
  }

  char* programcopy = file_name;
  char* tokens;
  size_t argc = 0;
  char* argv[64];
  while ((tokens = strtok_r(programcopy, " ", &programcopy))) {
    argv[argc] = malloc(sizeof(char*));
    strlcpy(argv[argc], tokens, strlen(tokens) + 1);
    argc += 1;
  }
  argv[argc] = NULL;
  //change the process name
  strlcpy(new_pcb->process_name, argv[0], strlen(argv[0]) + 1);
  /* Initialize interrupt frame and load executable. */
  if (success) {
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    success = load(file_name, &if_.eip, &if_.esp);
    input->success = success;

    /* Save kernel FPU. Init new FPU, Save.*/
    char fpu_buf[108];
    asm("fsave (%0); finit; fsave (%1); frstor (%2)" ::"g"(&fpu_buf), "g"(&if_.fpu), "g"(&fpu_buf));
    //UP semaphore when process loaded
    if (success) {
      //add child to parent child list;
      struct child_list_elem* child = malloc(sizeof(struct child_list_elem));

      memset(child, 0, sizeof(struct child_list_elem));

      child->pid = t->tid;
      child->exited = false;
      child->exit_code = -1;
      struct list_elem list = {NULL, NULL};
      child->elem = list;
      child->proc = new_pcb;
      list_push_back(&input->parent->children, &child->elem);
    }
    sema_up(&new_pcb->parent->sema_exec);
    if (!success) {
      if_.eax = -1;
      free(i);
      thread_exit();
    }

    push_to_stack(argc, argv, &if_);
  }

  /* Handle failure with succesful PCB malloc. Must free the PCB */
  if (!success && pcb_success) {
    // Avoid race where PCB is freed before t->pcb is set to NULL
    // If this happens, then an unfortuantely timed timer interrupt
    // can try to activate the pagedir, but it is now freed memory
    struct process* pcb_to_free = t->pcb;
    t->pcb = NULL;
    free(pcb_to_free);
  }

  /* Clean up. Exit on failure or jump to userspace */
  palloc_free_page(file_name);
  if (!success) {
    sema_up(&temporary);
    free(i);
    thread_exit();
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */

  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Waits for process with PID child_pid to die and returns its exit status.
   If it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If child_pid is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given PID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(pid_t child_pid UNUSED) {
  // sema_down(&temporary);

  struct list children = thread_current()->pcb->children;
  int exit_code = -1;
  bool foundChild = false;
  if (list_empty(&children)) {
    return -1;
  }
  /* Iterate through a process's children to down */
  struct list_elem* element;
  for (element = list_begin(&children); element != list_end(&children);
       element = list_next(element)) {
    struct child_list_elem* c = list_entry(element, struct child_list_elem, elem);
    pid_t entry_pid = c->pid;

    /* Finds child no matter if the child has exited or not */
    if (entry_pid == child_pid) {
      foundChild = true;
      /* Child has not been waited and hasn't exited */
      if (!c->waited && !c->exited) {
        c->waited = true;
        c->proc->waited = true;
        exit_code = c->exit_code;
        // Down
        sema_down(&c->proc->sema_wait);
        exit_code = c->exit_code;
        break;
      }
      // /* Child has not been waited and has exited */
      else if (!c->waited && c->exited) {
        c->waited = true;
        return c->exit_code;
      } else if (c->waited) {
        return -1;
      }
    }
    if (element->next == NULL) {
      break;
    }
  }

  if (!foundChild) {
    return -1;
  }
  return exit_code;
}

/* Free the current process's resources. */
void process_exit(void) {
  struct thread* cur = thread_current();
  uint32_t* pd;

  /* Close file if it exists */
  if (cur->pcb->f != NULL) {
    file_close(cur->pcb->f);
  }

  /* If this thread does not have a PCB, don't worry */
  if (cur->pcb == NULL) {
    thread_exit();
    NOT_REACHED();
  }

  struct process* parent = cur->pcb->parent;

  if (parent != NULL) {
    struct list children = parent->children;
    struct list_elem* element;

    for (element = list_begin(&children); element != list_end(&children);
         element = list_next(element)) {
      struct child_list_elem* c = list_entry(element, struct child_list_elem, elem);
      pid_t entry_pid = c->pid;
      if (cur->pcb->pid == entry_pid) {
        /* Set child element struct's exit code and status */
        c->exited = true;
        c->exit_code = cur->pcb->exit_code;
        break;
      }
    }
  }

  /* Up parent semaphore if is being waited upon */
  if (cur->pcb->waited) {
    sema_up(&cur->pcb->sema_wait);
  }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pcb->pagedir;
  if (pd != NULL) {
    /* Correct ordering here is crucial.  We must set
         cur->pcb->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
    cur->pcb->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }

  /* Freeing the File Descriptors and File Descriptor List */
  /* Also closes all the files in FD List*/
  struct fileDescriptor_list* fdt = cur->pcb->fileDescriptorTable;
  lock_acquire(&fdt->lock);
  struct list_elem* el;
  struct list_elem* next_el;
  for (el = list_begin(&fdt->lst); el != list_end(&fdt->lst); el = next_el) {
    next_el = list_next(el);
    struct fileDescriptor* fileDescriptor_entry = list_entry(el, struct fileDescriptor, elem);
    file_close(fileDescriptor_entry->file);
    list_remove(el);
    free(fileDescriptor_entry);
  }
  lock_release(&fdt->lock);
  free(cur->pcb->fileDescriptorTable);

  /* Free the PCB of this process and kill this thread
     Avoid race where PCB is freed before t->pcb is set to NULL
     If this happens, then an unfortuantely timed timer interrupt
     can try to activate the pagedir, but it is now freed memory */
  struct process* pcb_to_free = cur->pcb;
  cur->pcb = NULL;
  free(pcb_to_free);

  thread_exit();
}

/* Sets up the CPU for running user code in the current
   thread. This function is called on every context switch. */
void process_activate(void) {
  struct thread* t = thread_current();

  /* Activate thread's page tables. */
  if (t->pcb != NULL && t->pcb->pagedir != NULL)
    pagedir_activate(t->pcb->pagedir);
  else
    pagedir_activate(NULL);

  /* Set thread's kernel stack for use in processing interrupts.
     This does nothing if this is not a user process. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void** esp);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char* file_name, void (**eip)(void), void** esp) {
  struct thread* t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file* file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pcb->pagedir = pagedir_create();
  if (t->pcb->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  file = filesys_open(file_name);
  t->pcb->f = file;
  if (file == NULL) {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }
  file_deny_write(file);

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
      ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
                     Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
                     Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp))
    goto done;

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  // file_allow_write(file);
  //file_close(file);
  return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void*)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t* kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void** esp) {
  uint8_t* kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
      *esp = PHYS_BASE;
    else
      palloc_free_page(kpage);
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(void* upage, void* kpage, bool writable) {
  struct thread* t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
          pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
}

/* Returns true if t is the main thread of the process p */
bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }

/* Gets the PID of a process */
pid_t get_pid(struct process* p) { return (pid_t)p->main_thread->tid; }

/* Creates a new stack for the thread and sets up its arguments.
   Stores the thread's entry point into *EIP and its initial stack
   pointer into *ESP. Handles all cleanup if unsuccessful. Returns
   true if successful, false otherwise.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. You may find it necessary to change the
   function signature. */
bool setup_thread(void (**eip)(void) UNUSED, void** esp UNUSED, struct user_thread_input* input) {
  uint8_t* kpage;
  bool success = false;
  struct thread* t = thread_current();

  // TODO Keep track of how many pages have been installed
  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    // use for loop to iterate through user_thread_list from pcb
    int numPages = 0;
    while (!success) {
      numPages = numPages + 1;
      success = install_page(((uint8_t*)PHYS_BASE) - (PGSIZE * numPages), kpage, true);
    }
    *esp = (uint8_t*)PHYS_BASE - (PGSIZE * (numPages - 1));
    t->page = ((uint8_t*)PHYS_BASE) - (PGSIZE * numPages);
  }

  /* Setup the stack */
  /* align esp to 16 byte boundary */
  *esp = *esp - ((int)*esp % 16);

  /* first push 8 bytes of memory to maintain stack alignment */
  *esp = *esp - 8;

  /* Push tfun and arg onto the stack. */
  *esp = *esp - 4;
  memcpy(*esp, &input->args, 4);

  *esp = *esp - 4;
  memcpy(*esp, &input->function, 4);
  // *(if_.esp) = input->function;

  /* Push the rip*/
  *esp = *esp - 4;
  return success;
}

/* A thread function that creates a new user thread and starts it
   running. Responsible for adding itself to the list of threads in
   the PCB.
   This function will be implemented in Project 2: Multithreading and
   should be similar to start_process (). For now, it does nothing. */
static void start_pthread(void* exec_ UNUSED) {
  //create the new user thread
  //set interrupt
  struct thread* t = thread_current();

  struct user_thread_input* input = (struct user_thread_input*)exec_;
  t->pcb = input->pcb;
  process_activate();
  struct intr_frame if_;
  bool success;
  memset(&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  if_.eip = (void (*)(void))input->stub;

  success = setup_thread(&if_.eip, &if_.esp, input);

  //Add itself to list of threads in pcb

  struct user_thread_list_elem* thread_elem = malloc(sizeof(struct user_thread_list_elem));
  struct list_elem lst = {NULL, NULL};
  thread_elem->tid = t->tid;
  thread_elem->elem = lst;
  thread_elem->joined = false;
  thread_elem->joiner = NULL;
  thread_elem->exited = false;

  lock_acquire(&input->pcb->sherlock);
  list_push_back(&input->pcb->user_thread_list, &thread_elem->elem);
  lock_release(&input->pcb->sherlock);

  // push_to_stack(argc, argv, &if_);

  sema_up(&input->thread_sema_exec);

  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Starts a new thread with a new user stack running SF, which takes
   TF and ARG as arguments on its user stack. This new thread may be
   scheduled (and may even exit) before pthread_execute () returns.
   Returns the new thread's TID or TID_ERROR if the thread cannot
   be created properly.

   This function will be implemented in Project 2: Multithreading and
   should be similar to process_execute (). For now, it does nothing.
   */
tid_t pthread_execute(stub_fun sf UNUSED, pthread_fun tf UNUSED, void* arg UNUSED) {
  struct user_thread_input* input = malloc(sizeof(struct user_thread_input));
  input->function = tf;
  input->args = arg;
  input->stub = sf;
  input->pcb = thread_current()->pcb;

  /* Initialize thread's semaphore */
  struct semaphore semaphore_exec;
  input->thread_sema_exec = semaphore_exec;
  sema_init(&input->thread_sema_exec, 0);

  tid_t tid = thread_create("user", PRI_DEFAULT, start_pthread, input);

  /* Down the thread's associated semaphore */
  sema_down(&input->thread_sema_exec);

  return tid;
}

/* Waits for thread with TID to die, if that thread was spawned
   in the same process and has not been waited on yet. Returns TID on
   success and returns TID_ERROR on failure immediately, without
   waiting.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
tid_t pthread_join(tid_t tid UNUSED) {
  /* Obtain the thread we want to join on and set joiner elemnt*/
  struct list_elem* element;
  lock_acquire(&thread_current()->pcb->sherlock);
  struct list lst = thread_current()->pcb->user_thread_list;
  for (element = list_begin(&lst); element != list_end(&lst); element = list_next(element)) {
    struct user_thread_list_elem* u = list_entry(element, struct user_thread_list_elem, elem);
    if (u->tid == tid) {
      if (u->joined) {
        lock_release(&thread_current()->pcb->sherlock);
        return TID_ERROR;
      } else if (!u->exited) {
        intr_disable();
        u->joiner = thread_current();
        u->joined = true;
        thread_block();
        intr_enable();
        lock_release(&thread_current()->pcb->sherlock);
        return tid;
      } else {
        lock_release(&thread_current()->pcb->sherlock);
        return tid;
      }
    }
    if (element->next == NULL) {
      break;
    }
  }
  // lock_release(&thread_current()->pcb->sherlock);
  return TID_ERROR;
}

/* Free the current thread's resources. Most resources will
   be freed on thread_exit(), so all we have to do is deallocate the
   thread's userspace stack. Wake any waiters on this thread.

   The main thread should not use this function. See
   pthread_exit_main() below.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit(void) {
  struct thread* t = thread_current();
  lock_acquire(&t->pcb->sherlock);

  if (t->pcb->main_thread == t) {
    lock_release(&t->pcb->sherlock);
    pthread_exit_main();
  }

  palloc_free_page(pagedir_get_page(t->pcb->pagedir, t->page));
  pagedir_clear_page(t->pcb->pagedir, t->page);

  /* Let waiter go! */
  struct list_elem* element;
  struct list lst = thread_current()->pcb->user_thread_list;
  for (element = list_begin(&lst); element != list_end(&lst); element = list_next(element)) {
    struct user_thread_list_elem* u = list_entry(element, struct user_thread_list_elem, elem);
    if (u->tid == t->tid) {
      if (u->joined) {
        thread_unblock(u->joiner);
      }
      u->exited = true;
      break;
    }

    if (element->next == NULL) {
      break;
    }
  }
  lock_release(&t->pcb->sherlock);
  thread_exit();
}

/* Only to be used when the main thread explicitly calls pthread_exit.
   The main thread should wait on all threads in the process to
   terminate properly, before exiting itself. When it exits itself, it
   must terminate the process in addition to all necessary duties in
   pthread_exit.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit_main(void) {
  struct list_elem* element;
  lock_acquire(&thread_current()->pcb->sherlock);
  struct list lst = thread_current()->pcb->user_thread_list;
  for (element = list_begin(&lst); element != list_end(&lst); element = list_next(element)) {
    struct user_thread_list_elem* u = list_entry(element, struct user_thread_list_elem, elem);
    if (u->tid != thread_current()->tid) {
      pthread_join(u->tid);
    }
  }
  lock_release(&thread_current()->pcb->sherlock);
  thread_exit();
  process_exit();
}

bool validate_pointer(void* ptr) {
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
