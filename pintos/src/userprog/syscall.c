#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);
static struct lock filesystem_lock;


void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesystem_lock);
}

void create(struct intr_frame *f , const char *file, unsigned initial_size){
  lock_acquire(&filesystem_lock);
  f->eax = filesys_create(file, initial_size);
  lock_release(&filesystem_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{ 
  uint32_t* args = ((uint32_t*) f->esp);
  printf("System call number: %d\n", args[0]);
  if (args[0] == SYS_EXIT) {
    f->eax = args[1];
    printf("%s: exit(%d)\n", &thread_current ()->name, args[1]);
    thread_exit();
  }else if (args[0] == SYS_HALT){
    shutdown_power_off();
  }else if(args[0] == SYS_CREATE){
    create(f , (char* )args[1], (unsigned) args[2]);
  }
}
