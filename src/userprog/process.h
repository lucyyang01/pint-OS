#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdint.h>
#include <list.h>

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  //bool removed_cwd;
  uint32_t* pagedir;          /* Page directory. */
  char process_name[16];      /* Name of the main thread */
  struct thread* main_thread; /* Pointer to main thread */
  struct semaphore sema_exec;
  struct semaphore sema_wait;
  struct process* parent;
  struct list children;
  int ref_count;
  struct fileDescriptor_list* fileDescriptorTable;
  int exit_code;
  pid_t pid;
  bool waited;
  struct file* f;
  struct dir* cwd; /* Pointer to cwd, what should this be initialized to? */
};

/*children list elmenent*/
struct child_list_elem {
  pid_t pid;
  int exit_code;
  struct list_elem elem;
  bool waited;
  bool exited;
  struct process* proc;
};

struct fileDescriptor_list {
  int fdt_count; /* Counter for every file descriptor ever created*/
  struct list lst;
  struct lock lock;
};

struct fileDescriptor {
  int fd;
  bool is_dir;
  struct file* file;
  struct dir* dir;
  struct list_elem elem;
};

void userprog_init(void);

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

/* Process Input when running start_process */
struct process_input {
  char* file_name;
  struct process* parent;
  bool success;
};

void pthread_exit(void);
void pthread_exit_main(void);
bool validate_pointer(void* ptr);

#endif /* userprog/process.h */