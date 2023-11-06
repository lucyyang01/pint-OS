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
  uint32_t* pagedir;          /* Page directory. */
  char process_name[16];      /* Name of the main thread */
  struct thread* main_thread; /* Pointer to main thread */

  /* Synchronization variables */
  struct semaphore sema_exec;
  struct semaphore sema_wait;
  struct lock sherlock;  /* Locks most of PCB variables*/
  struct lock user_lock; /* Locks list of user locks */
  struct lock sema_lock; /* Locks list of user semaphores */

  struct process* parent;
  struct list children;
  int ref_count;
  struct fileDescriptor_list* fileDescriptorTable;
  int exit_code;
  pid_t pid;
  bool waited;
  struct file* f;
  struct list user_thread_list;
  struct list user_lock_list; /* list of locks held by a process */
  struct list user_semaphore_list;
};

struct user_semaphore_list_elem {
  struct semaphore sema;
  char* sema_id;
  struct list_elem elem;
};

struct user_lock_list_elem {
  struct lock lock;
  char* lock_id;
  struct list_elem elem;
};

struct user_thread_list_elem {
  tid_t tid;
  bool joined;
  bool exited;
  struct semaphore sema_join;
  struct list_elem elem;
  struct thread* joiner /* NULL if never joined on ELSE equal to joinee */
};

/*children list elmenent*/
struct child_list_elem {
  pid_t pid;
  int exit_code;
  struct list_elem elem;
  bool waited;
  bool exited;
  struct process* proc;
  struct lock watson;
};

struct fileDescriptor_list {
  int fdt_count; /* Counter for every file descriptor ever created*/
  struct list lst;
  struct lock lock;
};

struct fileDescriptor {
  int fd;
  struct file* file;
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

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);
bool validate_pointer(void* ptr);

#endif /* userprog/process.h */