#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdint.h>

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
  uint32_t* pagedir;                               /* Page directory. */
  char process_name[16];                           /* Name of the main thread */
  struct thread* main_thread;                      /* Pointer to main thread */
  struct semaphore sema;                           /* Semaphore that waits for children */
  struct process* parent;                          /* Parent process to increment semaphore */
  struct list children;                            /* Pintos list of child structs*/
  int ref_count;                                   /* All the threads currently running*/
  struct fileDescriptor_list* fileDescriptorTable; /* List of file descriptors */
  int exit_code;                                   /* Exit code for Parent Processes */
  bool waited;                                     /* Being waited on or not */
  pid_t pid;
};

struct process_input {
  char* file_name;
  struct process* parent;
};

struct fileDescriptor_list {
  int fdt_count; /* Counter for every file descriptor ever created*/
  struct list lst;
  struct lock lock;
};

struct fileDescriptor {
  //TODO: check process_execute for list init
  int fd; //entry to global descriptor table
  struct file* file;
  struct list_elem elem;
};

struct child_elem {
  struct process* process;
  int completion_status;
  struct list_elem elem;
};

void userprog_init(void);

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

#endif /* userprog/process.h */
