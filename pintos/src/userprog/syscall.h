#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "list.h"
//File List
struct file_list_data {
  struct list_elem elem;
  int fd;
  struct file * file_struct;
  const char * file_name;
};

void syscall_init (void);
typedef int pid_t;
#endif /* userprog/syscall.h */
