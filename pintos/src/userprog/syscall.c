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
#include "filesys/directory.h"
#ifdef VM
#include "vm/page.h"
#include "vm/frame.h"
#endif


//Function Declarations
bool is_valid_ptr(void* pptr, size_t size);
bool is_valid_str(char* ptr);
bool are_valid_args(uint32_t* ptr, size_t num_args);
struct file_node* get_file_node_from_fd(int givenFd);
void exit_with_error_code(struct intr_frame *f);
typedef void syscall_fun_t(struct intr_frame *f UNUSED); 

struct mmap_node* get_mmap_node_by_id(int id);

//Variable
static struct lock filesystem_lock;

static void syscall_handler (struct intr_frame *);


typedef struct sycall_desc {
  syscall_fun_t *fun; //Function that should be done
} syscall_desc_t;

//Declaration of functions/System Calls
syscall_fun_t syscall_halt, syscall_exit, syscall_exec, syscall_wait, //Process System Calls
              syscall_create, syscall_remove, syscall_open, syscall_filesize, //File System Calls
              syscall_read, syscall_write, syscall_seek, syscall_tell, syscall_close,
              syscall_chdir, syscall_mkdir, syscall_readdir, syscall_isdir, syscall_inumber,
              empty_function_first, empty_function_sec,
#ifdef VM
              syscall_practice, syscall_mmap, syscall_munmap;
#else
              empty_function_first, 
              empty_function_sec,
              syscall_practice; //Practice System Call
#endif
              


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
#ifdef VM
  {syscall_mmap},
  {syscall_munmap},
#endif
  //Project 4
  {empty_function_first},
  {empty_function_sec},
  {syscall_chdir},
  {syscall_mkdir},
  {syscall_readdir},
  {syscall_isdir},
  {syscall_inumber}
};

/////////////////////////////////////
void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesystem_lock);
}


static void
syscall_handler (struct intr_frame *f UNUSED)
{ 
  if(!is_valid_ptr(f->esp , sizeof(int))) thread_exit();
  int syscallNumber = *(int*)f->esp;
  syscall_table[syscallNumber].fun(f);
}


//Process System Calls #########################################################################

/* A “fake” system call that doesn’t exist in any modern operating system
 */
void syscall_practice(struct intr_frame *f UNUSED) {
  uint32_t *arguments = (uint32_t*)f->esp;

  if (!are_valid_args(&arguments[1], 1))
    thread_exit();

  f->eax = arguments[1] + 1;
}

/* Terminates Pintos by calling shutdown_power_off()
 */
void syscall_halt(struct intr_frame *f UNUSED){
  shutdown_power_off();
}

/* Terminates the current user program, returning status to the kernel
 */
void syscall_exit(struct intr_frame *f UNUSED) {
  uint32_t *arguments = (uint32_t*)f->esp;
  if (!are_valid_args(&arguments[1], 1))
    thread_exit();

  f->eax = arguments[1];
  thread_current()->process_node->status = arguments[1]; 
  thread_exit();
}

/* Runs the executable whose name is given in cmd_line, passing any given arguments, 
 * and returns the new process’s program id (pid)
 */
void syscall_exec(struct intr_frame *f UNUSED) {
  uint32_t *arguments = (uint32_t*)f->esp;

  if (!are_valid_args(&arguments[1], 1) || !is_valid_str(arguments[1]))
    exit_with_error_code(f);

  char* cmd_line = (char*)arguments[1];
  if(!is_valid_str(cmd_line)) exit_with_error_code(f);
  f->eax = process_execute(cmd_line);
}

/* Waits for a child process pid and retrieves the child’s exit status.
 * If pid is still alive, waits until it terminates. 
 * Then, returns the status that pid passed to exit
 */
void syscall_wait(struct intr_frame *f UNUSED){
  uint32_t *arguments = (uint32_t*)f->esp;
  if (!are_valid_args(&arguments[1], 1)){
    f->eax = -1;
    thread_exit();
  }
    
  tid_t tid = (tid_t)arguments[1];
  f->eax = process_wait(tid);
}



//File System Calls ##################################################################

/* Creates a new file called file initially initial size bytes in size. 
 * Returns true if successful, false otherwise.
 */
void syscall_create(struct intr_frame *f){
  if(!is_valid_ptr(f->esp , 3 * sizeof(int))) exit_with_error_code(f);
  uint32_t *arguments = (uint32_t*)f->esp;
  char* file = (char*)arguments[1];
  unsigned initial_size = (unsigned) arguments[2];
  if(!is_valid_str(file)) exit_with_error_code(f);
  lock_acquire(&filesystem_lock);
  f->eax = filesys_create(file, initial_size, false);
  lock_release(&filesystem_lock);
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

/* Opens the file called file. 
 * Returns a nonnegative integerhandle called a “file descriptor” (fd), 
 * or -1 if the file could not be opened.
 */
void syscall_open(struct intr_frame *f UNUSED){
  if(!is_valid_ptr(f->esp , 2 * sizeof(int))) exit_with_error_code(f);
  uint32_t *arguments = (uint32_t*)f->esp;
  char* filename = (char*)arguments[1];
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
  new_node->dir = NULL;
  f->eax = fd;
  struct inode *inode = file_get_inode(file);
  if(inode && is_directory(inode))
    new_node->dir = dir_open(inode_reopen(inode));

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
  }
  
  lock_acquire(&filesystem_lock);
  struct file_node *file_node = get_file_node_from_fd(fd);
  f->eax = file_length(file_node->file);
  lock_release(&filesystem_lock);
}

/* Returns the size, in bytes, of the file open as fd.
 * Returns the number of bytes actually read (0 at end of file), 
 * or -1 if the file could not be read 
 */
void syscall_read(struct intr_frame *f UNUSED){
  if(!is_valid_ptr(f->esp , 3 * sizeof(int))){
    f->eax = -1;
    thread_exit();
  } 
  uint32_t *arguments = (uint32_t*)f->esp;
  int fd = (int)arguments[1];
  char* buffer = (char*) arguments[2];
  unsigned size = (unsigned) arguments[3];
  if(!(is_user_vaddr(buffer) && is_user_vaddr(buffer + size - 1))){
    f->eax = -1;
    thread_exit();
  }
  #ifdef VM
  if(get_frame_wrapper(false, 0, buffer, thread_current()->page_table) == NULL && buffer < f->esp - 32){
    f->eax = -1;
    thread_exit();
  }
  #endif
  lock_acquire(&filesystem_lock);
  memset(buffer, 0 , size);
  if (!are_valid_args(&arguments[1], 1) || !is_valid_ptr(arguments[2], arguments[3])){
    f->eax = -1;
    lock_release(&filesystem_lock);
    thread_exit();
  }
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
    #ifdef VM
    void * pg;
    void * frame;
    for (pg = pg_round_down(buffer); pg < buffer + size; pg += PGSIZE) {
      frame = get_frame_wrapper(false, 0, pg, thread_current()->page_table);
      change_evict_status(frame, true);
    }
    #endif 
    f->eax = file_read(file_node->file, buffer, size);
    #ifdef VM
    for (pg = pg_round_down(buffer); pg < buffer + size; pg += PGSIZE) {
      frame = get_frame_wrapper(false, 0, pg, thread_current()->page_table);
      change_evict_status(frame, false);
    }
    #endif 
  }
  lock_release(&filesystem_lock);
}


/* Writes size bytes from buffer to the open file fd. 
 * Returns the number of bytes actually written, which may be less than size
 * if some bytes could not be written.
 */
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
      #ifdef VM
      void * pg;
      void * frame;
      for (pg = pg_round_down(buff); pg < buff + size; pg += PGSIZE) {
        frame = get_frame_wrapper(false, 0, pg, thread_current()->page_table);
        change_evict_status(frame, true);
      }
      #endif 
      f->eax = file_write(file_node->file, buff, size);
      #ifdef VM
      for (pg = pg_round_down(buff); pg < buff + size; pg += PGSIZE) {
        frame = get_frame_wrapper(false, 0, pg, thread_current()->page_table);
        change_evict_status(frame, false);
      }
      #endif
    } else {
      f->eax = -1;
    }
  }
  lock_release(&filesystem_lock);
}


/* Changes the next byte to be read or written in open file fd to position, 
 * expressed in bytes from the beginning of the file
 */
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


/* Returns the position of the next byte to be read or written in open file fd, 
 * expressed in bytes from the beginning of the file.
 */
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

/* Closes file descriptor fd
 */
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
  dir_close(file_node->dir);
  list_remove(&(file_node->elem));
  free(file_node);
  lock_release(&filesystem_lock);
}

#ifdef VM
void syscall_mmap(struct intr_frame *f){
  uint32_t *arguments = (uint32_t*)f->esp;

  int fd = arguments[1];
  void * base_addr = (void*)arguments[2];
  if(base_addr == NULL || pg_ofs(base_addr) || fd <= 1) {
    f->eax = -1;
    return;
  }
  struct thread * current_thread = thread_current();

  lock_acquire(&filesystem_lock);

  struct file_node * file_node = get_file_node_from_fd(fd);
  if(file_node == NULL || file_node->file == NULL){
    f->eax = -1;
    lock_release(&filesystem_lock);
    return;
  }

  struct file * reopened_file;
  reopened_file = file_reopen(file_node->file);
  if (reopened_file == NULL || file_length(reopened_file) == 0) {
    f->eax = -1;
    lock_release(&filesystem_lock);
    return;
  }

  size_t i, file_len;
  file_len = file_length(reopened_file);
  for (i = 0; i < file_len; i += PGSIZE) {
    void * curr_page;
    curr_page = base_addr + i;
    
    void* frame;
    frame = get_frame_wrapper(false, 0, curr_page, thread_current()->page_table);
    if(frame == NULL) frame = pagedir_get_page(thread_current()->pagedir , curr_page);
    // check if this page is free, else wrire -1 in f->eax and return
    if (frame != NULL) {
      f->eax = -1;
      lock_release(&filesystem_lock);
      return;
    }
  }

  struct mmap_node * new_mmap_node; 
  new_mmap_node = (struct mmap_node *)malloc(sizeof(struct mmap_node));
  new_mmap_node->mapped_file = reopened_file;
  new_mmap_node->base_addr = base_addr;
  
  current_thread->max_mmap_node_id += 1;
  new_mmap_node->id = current_thread->max_mmap_node_id;
  list_push_back(&current_thread->mmap_node_list, &new_mmap_node->elem);

  for (i = 0; i < file_len; i += PGSIZE) {
    void * curr_page;
    curr_page = base_addr + i;

    size_t read_bytes_size;
    read_bytes_size = (i + PGSIZE < file_len ? PGSIZE : file_len - i);

    // register this page in supplementary page table
    page_table_mmap(thread_current()->page_table, curr_page, reopened_file, i, true, read_bytes_size);
  }

  // write new nodes id into f->eax
  f->eax = new_mmap_node->id;
  lock_release(&filesystem_lock);
}

void syscall_munmap_wrapper(int id) {
  lock_acquire(&filesystem_lock);

  struct mmap_node * node = get_mmap_node_by_id(id);
  if(node == NULL){
    lock_release(&filesystem_lock);
    return;
  }

  struct file * file;
  file = file_reopen(node->mapped_file);

  size_t i, file_len;
  file_len = file_length(file);
  for (i = 0; i < file_len; i += PGSIZE) {
    void * curr_page;
    curr_page = node->base_addr + i;
    
    size_t size;
    size = (i + PGSIZE < file_len) ? PGSIZE : (file_len - i);

    page_table_unmap(thread_current()->page_table, curr_page, size);
  }
  list_remove(&node->elem);
  lock_release(&filesystem_lock);
}

void syscall_munmap(struct intr_frame *f){
  uint32_t *arguments = (uint32_t*)f->esp;
  int id = arguments[1];
  syscall_munmap_wrapper(id);
}
#endif

//Project 4
void syscall_chdir(struct intr_frame *f){
  uint32_t *arguments = (uint32_t*)f->esp;
  //TODO: check arguments
  char *dir_name = (char *)arguments[1];
  struct dir* dir = dir_open_with_path(dir_name);
  if(dir == NULL){
    f->eax = 0; //Return false
  } else {
    dir_close (thread_current()->cwd); //Close previous dir
    thread_current()->cwd = dir; //Set current working directory
    f->eax = 1; //Return True
  }
}
void syscall_mkdir(struct intr_frame *f){
  uint32_t *arguments = (uint32_t*)f->esp;
  //TODO: check arguments
  char *dir_name = (char *)arguments[1];
  bool result = filesys_create(dir_name, 0, true);
  f->eax = result;
}
void syscall_readdir(struct intr_frame *f){

}
void syscall_isdir(struct intr_frame *f){
  
}
void syscall_inumber(struct intr_frame *f){
  
}

void empty_function_first(struct intr_frame *f){
}
void empty_function_sec(struct intr_frame *f){
}
//Helpers #############################################################################

/* Checks whether given poiner is valid
 */
bool is_valid_ptr(void* pptr, size_t size) {
  if (pptr == NULL)
    return false;

  char* ptr = (char*)pptr;
  bool res = true;
  unsigned i = 0;
  struct thread* current_thread = thread_current();
  for(; i < size; i++){
    if(!is_user_vaddr(ptr + i)){
      return false;
    }
    
    #ifdef VM
    struct hash* page_table = current_thread->page_table;
    if (get_frame_wrapper(false, 0, ptr + i, page_table) == NULL) {
      res = false;
    }
    #endif
    uint32_t pd = current_thread->pagedir; // optional field #ifdef USERPROG
    if (pagedir_get_page(pd, ptr + i) == NULL){
      res = false;
    }
  }
  return res;
}

/* Checks whether given string is valid
 */
bool is_valid_str(char* ptr) {
  if(ptr == NULL) return false;
  if(!is_valid_ptr((void*)ptr , 1)) return false;
  char *p;
  
  for (p = ptr; is_valid_ptr((void*)p , 1) && *p != '\0'; p++)
    continue;
  
  return true;
}

/* Checks whether arguments are valid
 */
bool are_valid_args(uint32_t* ptr, size_t num_args) {
  return is_valid_ptr(ptr, num_args * sizeof(uint32_t));
}

/* Get file according to fd
 */
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

#ifdef VM
/* Get mmap_node according to id
 */
struct mmap_node* get_mmap_node_by_id(int id) {
  struct list_elem* e; 
  struct list* curr_list = &(thread_current()->mmap_node_list);

  if(list_size(curr_list) == (size_t)(0)) return NULL;
  for(e = list_begin (curr_list); e != list_end (curr_list); e = list_next (e)){
    struct mmap_node * curr_node = list_entry (e, struct mmap_node, elem); 
    if(curr_node->id == id){ 
      return curr_node;
    }
  }
  return NULL;
}
#endif

/* Returns -1 and exits
 */
void exit_with_error_code(struct intr_frame *f){
  f->eax = -1;
  thread_exit();
}

