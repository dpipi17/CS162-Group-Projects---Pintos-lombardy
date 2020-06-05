#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "lib/user/syscall.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct process_node {
  struct list_elem elem;
  pid_t pid;                    
  struct semaphore semaphore;    
  int status;          
  bool successful;             
};

struct mmap_node {
  struct list_elem elem;
  
  int id;
  struct file * mapped_file;
  void * base_addr;
};


#endif /* userprog/process.h */
