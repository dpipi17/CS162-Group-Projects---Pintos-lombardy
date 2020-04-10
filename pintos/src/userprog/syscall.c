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
#include "lib/kernel/list.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/malloc.h"

struct file_node* get_file_node_from_fd(int givenFd);
static void syscall_handler (struct intr_frame *);
static struct lock filesystem_lock;

typedef void syscall_fun_t(struct intr_frame *f UNUSED); 
void clear_files_and_exit();
void exit_with_error_code(struct intr_frame *f UNUSED);

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
  {syscall_halt},
  {syscall_exit},
  {syscall_exec},
  {syscall_wait}, 

  //File System Calls
  {syscall_create},
  {syscall_remove},
  {syscall_open},
  {syscall_filesize},
  {syscall_read},
  {syscall_write},
  {syscall_seek},
  {syscall_tell},
  {syscall_close},

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
  if (pptr == NULL)
    return false;

  char* ptr = (char*)pptr;
  if (!is_user_vaddr(ptr) || !is_user_vaddr(ptr + size - 1))
    return false;
  
  struct thread* current_thread = thread_current();
  uint32_t pd = current_thread->pagedir; // optional field #ifdef USERPROG

  if (pagedir_get_page(pd, ptr) == NULL || pagedir_get_page(pd, ptr + size - 1) == NULL)
    return false;

  return true;
}

bool is_valid_str(char* ptr) {
  if(ptr == NULL) return false;
  if(!is_valid_ptr((void*)ptr , 1)) return false;
  char *p;
  
  for (p = ptr; is_valid_ptr((void*)p , 1) && *p != '\0'; p++)
    continue;
  
  return true;
}

bool are_valid_args(uint32_t* ptr, size_t num_args) {
  return is_valid_ptr(ptr, num_args * sizeof(uint32_t));
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{ 
  if(!is_valid_ptr(f->esp , sizeof(int))) thread_exit();
  uint32_t* args = ((uint32_t*) f->esp);

  int syscallNumber = *(int*)f->esp;
  syscall_table[syscallNumber].fun(f);
}

void syscall_wait(struct intr_frame *f UNUSED){
  uint32_t *arguments = (uint32_t*)f->esp;
  if (!are_valid_args(&arguments[1], 1)){
    f->eax = -1;
    thread_exit();
  }
    
  tid_t tid = (tid_t)arguments[1];
  f->eax = process_wait(tid);
}

/* Deletes the file called fileName. 
 * Returns true if successful, false otherwise
 */
void syscall_remove(struct intr_frame *f UNUSED){
  lock_acquire(&filesystem_lock);
  uint32_t *arguments = (uint32_t*)f->esp;
  if (!are_valid_args(&arguments[1], 1) || !is_valid_str(arguments[1])){
    f->eax = 0;
    lock_release(&filesystem_lock);
    thread_exit();
  }
  char* fileName = (char*)arguments[1];
  f->eax = filesys_remove(fileName); 
  lock_release(&filesystem_lock);
}

/* Returns the size, in bytes, of the file open as fd
 */
void syscall_filesize(struct intr_frame *f UNUSED){
  uint32_t *arguments = (uint32_t*)f->esp;
  int fd = (int)arguments[1];
  if (!are_valid_args(&arguments[1], 1)){
    f->eax = -1;
    return;
    //thread_exit();
  }
    
  lock_acquire(&filesystem_lock);
  struct file_node *file_node = get_file_node_from_fd(fd);
  f->eax = file_length(file_node->file);
  lock_release(&filesystem_lock);
}

/* Returns the size, in bytes, of the file open as fd
 */
void syscall_read(struct intr_frame *f UNUSED){
  lock_acquire(&filesystem_lock);
  if(!is_valid_ptr(f->esp , 3 * sizeof(int))){
    f->eax = -1;
    thread_exit();
  } 
  uint32_t *arguments = (uint32_t*)f->esp;
  if (!are_valid_args(&arguments[1], 1) || !is_valid_str(arguments[2])){
    f->eax = -1;
    lock_release(&filesystem_lock);
    thread_exit();
  }
  int fd = (int)arguments[1];
  char* buffer = (char*) arguments[2];
  unsigned size = (unsigned) arguments[3];
  if(fd == 0){ //Case when read from keybord  
    unsigned i;
    for(i = 0; i < size; i++){
      buffer[i] = input_getc();
    }
    f->eax = size;
  } else {
    struct file_node *file_node = get_file_node_from_fd(fd);
    if(file_node == NULL) {
      f->eax = -1;
      lock_release(&filesystem_lock);
      return;
    }
    f->eax = file_read(file_node->file, buffer, size);
  }
  lock_release(&filesystem_lock);
}

void syscall_practice(struct intr_frame *f UNUSED) {
  uint32_t *arguments = (uint32_t*)f->esp;

  if (!are_valid_args(&arguments[1], 1))
    thread_exit();

  f->eax = arguments[1] + 1;
}

void syscall_exec(struct intr_frame *f UNUSED) {
  uint32_t *arguments = (uint32_t*)f->esp;

  if (!are_valid_args(&arguments[1], 1) || !is_valid_str(arguments[1]))
    exit_with_error_code(f);

  char* cmd_line = (char*)arguments[1];
  if(!is_valid_str(cmd_line)) exit_with_error_code(f);
  f->eax = process_execute(cmd_line);
}

void syscall_exit(struct intr_frame *f UNUSED) {
  uint32_t *arguments = (uint32_t*)f->esp;
  if (!are_valid_args(&arguments[1], 1))
    thread_exit();

  f->eax = arguments[1];
  thread_current()->process_node->status = arguments[1]; 
  thread_exit();
}

void syscall_halt(struct intr_frame *f UNUSED){
  shutdown_power_off();
}

void syscall_open(struct intr_frame *f UNUSED){
  if(!is_valid_ptr(f->esp , 2 * sizeof(int))) exit_with_error_code(f);
  uint32_t *arguments = (uint32_t*)f->esp;
  char* filename = arguments[1];
  if(!is_valid_str(filename)) exit_with_error_code(f);
  
  lock_acquire(&filesystem_lock);
  int fd = thread_current()->fd_counter++;
  struct file* file = filesys_open(filename);
  if(file == NULL){
    lock_release(&filesystem_lock);
    f->eax = -1;
    return;
  }
  struct file_node* new_node = malloc(sizeof(struct file_node));
  list_push_back(&(thread_current()->file_list) , &(new_node ->elem));
  new_node->fd = fd;
  new_node->file = file;
  f->eax = fd;
  lock_release(&filesystem_lock);
}

void syscall_create(struct intr_frame *f){
  if(!is_valid_ptr(f->esp , 3 * sizeof(int))) exit_with_error_code(f);
  uint32_t *arguments = (uint32_t*)f->esp;
  char* file = (char*)arguments[1];
  unsigned initial_size = (unsigned) arguments[2];
  if(!is_valid_str(file)) exit_with_error_code(f);
  lock_acquire(&filesystem_lock);
  f->eax = filesys_create(file, initial_size);
  lock_release(&filesystem_lock);
}

void syscall_write(struct intr_frame *f) {
  uint32_t *arguments = (uint32_t*)f->esp;
  if (!are_valid_args(&arguments[1], 3) || !is_valid_ptr(arguments[2], arguments[3]))
    thread_exit();
  
  int fd = arguments[1];
  char* buff = (char*)arguments[2];
  uint32_t size = (uint32_t)arguments[3];

  lock_acquire(&filesystem_lock);
  if (fd == 1) {
    putbuf(buff, size);
    f->eax = size;
  } else {
    struct file_node* file_node = get_file_node_from_fd(fd);
    if (file_node != NULL) {
      f->eax = file_write(file_node->file, buff, size);
    } else {
      f->eax = -1;
    }
  }
  lock_release(&filesystem_lock);
}

void syscall_seek(struct intr_frame *f){
  if(!is_valid_ptr(f->esp , 3 * sizeof(int))) thread_exit();
  lock_acquire(&filesystem_lock);

  uint32_t *arguments = (uint32_t*)f->esp;
  struct file_node *file_node = get_file_node_from_fd(arguments[1]);
  if(file_node == NULL){
    f->eax = -1;
    lock_release(&filesystem_lock);
    return;
  }
  file_seek (file_node->file, arguments[2]);
  
  lock_release(&filesystem_lock);
}

void syscall_tell(struct intr_frame *f){
  if(!is_valid_ptr(f->esp , 2 * sizeof(int))) thread_exit();
  lock_acquire(&filesystem_lock);

  uint32_t *arguments = (uint32_t*)f->esp;
  struct file_node *file_node = get_file_node_from_fd(arguments[1]);
  if(file_node == NULL){
    f->eax = -1;
    lock_release(&filesystem_lock);
    return;
  }
  file_tell (file_node->file);
  
  lock_release(&filesystem_lock);
}

struct file_node* get_file_node_from_fd(int givenFd){
  struct list_elem* e; 
  struct list* curr_list = &(thread_current()->file_list);

  if(list_size(curr_list) == (size_t)(0)) return NULL;
  for(e = list_begin (curr_list); e != list_end (curr_list); e = list_next (e)){
    struct file_node* curr_file = list_entry (e, struct file_node, elem); //One of my files
    if(curr_file->fd == givenFd){ 
      return curr_file;
    }
  }
  return NULL;
}

void syscall_close(struct intr_frame *f){
  if(!is_valid_ptr(f->esp , 2 * sizeof(int))) return;
  uint32_t *arguments = (uint32_t*)f->esp;
  if(arguments[1] == 0 || arguments[1] == 1) return;
  lock_acquire(&filesystem_lock);
  struct file_node * file_node = get_file_node_from_fd(arguments[1]);
  if(file_node == NULL){
    f->eax = -1;
    lock_release(&filesystem_lock);
    return;
  }
  list_remove(&(file_node->elem));
  free(file_node);
  lock_release(&filesystem_lock);
}


void exit_with_error_code(struct intr_frame *f){
  f->eax = -1;
  thread_exit();
}

