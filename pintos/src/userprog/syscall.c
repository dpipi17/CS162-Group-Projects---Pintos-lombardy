#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "lib/string.h"

static void syscall_handler (struct intr_frame *);
static struct lock filesystem_lock;

typedef void syscall_fun_t(struct intr_frame *f UNUSED); 

typedef struct sycall_desc {
  syscall_fun_t *fun; //Function that should be done
  //int syscallNumber; //Number of syscall - მგონი არ გვინდა ხო NUMBER/ENUM ებია და...
} syscall_desc_t;

//Declaration of functions/System Calls
syscall_fun_t syscall_halt, syscall_exit, syscall_exec, syscall_wait, //Process System Calls
              syscall_create, syscall_remove, syscall_open, syscall_filesize, //File System Calls
              syscall_read, syscall_write, syscall_seek, syscall_tell, syscall_close,
              syscall_practice; //Practice System Call

//
syscall_desc_t syscall_table[] = {
  //Process System Calls
  // {syscall_halt},
  {syscall_exit},
  {syscall_exec},
  {syscall_wait}, 

  //File System Calls
  {syscall_create},
  {syscall_remove},
  //{syscall_open},
  ///{syscall_filesize},
  //{syscall_read},
  //{syscall_write},
  //{syscall_seek},
  //{syscall_tell},
  //{syscall_close},

  //Practice System Call
  {syscall_practice},
};

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesystem_lock);
}

bool is_valid_ptr(void* pptr, size_t size) {
  char* ptr = *(char**)pptr;
  if (!is_user_vaddr(ptr) || !is_user_vaddr(ptr + size))
    return false;
  
  struct thread* current_thread = thread_current();
  uint32_t pd = current_thread->pagedir; // optional field #ifdef USERPROG

  if (pagedir_get_page(pd, ptr) == NULL || pagedir_get_page(pd, ptr + size) == NULL)
    return false;

  return true;
}

bool is_valid_str(char* ptr) {
  size_t len = strlen(ptr); 
  return is_valid_ptr(ptr, len + 1); 
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{ 
  uint32_t* args = ((uint32_t*) f->esp);
  printf("System call number: %d\n", args[0]);

  int syscallNumber = *(int*)f->esp;
  syscall_table[syscallNumber].fun(f); 
  /* Ditosi
  if (args[0] == SYS_EXIT) {
    f->eax = args[1];
    printf("%s: exit(%d)\n", &thread_current ()->name, args[1]);
    thread_exit();
  }else if (args[0] == SYS_HALT){
    shutdown_power_off();
  }else if(args[0] == SYS_CREATE){
    create(f , (char* )args[1], (unsigned) args[2]);
  }
  */
}


void syscall_wait(struct intr_frame *f UNUSED){
  uint32_t *arguments = (uint32_t*)f->esp;
  tid_t tid = (tid_t)arguments[1];
  f->esp = process_wait(tid);
}


void syscall_create(struct intr_frame *f){
  lock_acquire(&filesystem_lock);
  uint32_t *arguments = (uint32_t*)f->esp;
  char* file = (char*)arguments[1];
  unsigned initial_size = (unsigned) arguments[2];
  f->eax = filesys_create(file, initial_size);
  lock_release(&filesystem_lock);
}


void syscall_remove(struct intr_frame *f UNUSED){
  uint32_t *arguments = (uint32_t*)f->esp;
  char* fileName = (char*)arguments[1];
  //TODO: Need Gega check
  f->eax = filesys_remove(fileName); 
}

void syscall_practice(struct intr_frame *f UNUSED) {
  uint32_t *arguments = (uint32_t*)f->esp;
  f->eax = arguments[1] + 1;
}

void syscall_exec(struct intr_frame *f UNUSED) {
  uint32_t *arguments = (uint32_t*)f->esp;
  char* cmd_line = (char*)arguments[1];
  f->eax = process_execute(cmd_line);
}

void syscall_exit(struct intr_frame *f UNUSED) {
  uint32_t *arguments = (uint32_t*)f->esp;
  f->eax = arguments[1];
  printf("%s: exit(%d)\n", &thread_current ()->name, arguments[1]);
  thread_exit();
}