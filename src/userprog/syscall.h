#include <stdbool.h>
#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);
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
#endif /* userprog/syscall.h */
