#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "threads/synch.h"

//Forward function declarations
static void syscall_handler (struct intr_frame *);
static int write(int fd, const void *buffer, unsigned size);
static void exit(int status);
static void halt(void);
static bool create(const char * file ,unsigned initial_size);
static int open(const char * file);
static void close(int fd);
static bool remove(const char * file);
static void init_file_data(struct file_list_data * f, int fd, struct file * file_struct, const char * file_name);
static int filesize(int fd);
static int read(int fd, void *buffer, unsigned size);
static pid_t exec(const char * cmd_line);
static int wait(pid_t pid);
static void seek(int fd, unsigned position);
static unsigned tell (int fd);

//Finds a file on the file_list given its fd
static struct file_list_data * find_file_data(struct list * file_list, int fd); 

//Checks a pointer's validity
static void check_pointer(int* ptr);

//Gets argc arguments from the stack, and stores them in args[]
static void get_syscall_args (int* args, void* esp, int argc);

//Global filesystem lock
static struct lock file_sys_lock;

//Next file descriptor value
static int fd_next;

//Max number of arguments
const int MAX_ARGS = 128;

//First available file descriptor (0 and 1 are reserved)
const int FIRST_FD = 2;

//Define lowest point in user memory
const int USER_BASE = 0x08048000;

//Initializes our file data struct with given values
static void init_file_data(struct file_list_data * f, int fd, struct file * file_struct, const char * file_name) {
  f->fd = fd;
  f->file_struct = file_struct;
  f->file_name = file_name;
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_sys_lock);
  fd_next = FIRST_FD;
}

static void
syscall_handler (struct intr_frame *f) 
{
  //Get the syscall, and check its validity
  int *sys_call;
  check_pointer(f->esp);
  sys_call = (int*)f->esp;

  //Initialize the args array
  int args[MAX_ARGS];

  //Execute a function based on sys_call:
  //Each block gets the necessary args from the stack,
  //checks them if necessary, runs the function, and
  //updates f->eax if there is a return type
  switch(*sys_call) {
  	case SYS_WRITE:
      get_syscall_args(args, f->esp, 3);
      check_pointer((int *)args[1]);
  		f->eax = write(args[0], (const void*)args[1], (unsigned)args[2]);
  		break;
  	case SYS_EXIT:
      get_syscall_args(args, f->esp, 1);
  		exit(args[0]);
  		break;
    case SYS_HALT:
      halt();
      break;
    case SYS_CREATE:
      get_syscall_args(args, f->esp, 2);
      check_pointer((int *)args[0]);
      f->eax = create((const char*)args[0], args[1]);
      break;
    case SYS_REMOVE:
      get_syscall_args(args, f->esp, 1);
      check_pointer((int *)args[0]);
      f->eax = remove((const char*)args[0]);
      break;
    case SYS_OPEN:
      get_syscall_args(args, f->esp, 1);
      check_pointer((int *)args[0]);
      f->eax = open((const char*)args[0]);
      break;
    case SYS_FILESIZE:
      get_syscall_args(args, f->esp, 1);
      f->eax = filesize((int)args[0]);
      break;
    case SYS_READ:
      get_syscall_args(args, f->esp, 3);
      check_pointer((int *)args[1]);
      f->eax = read((int)args[0],(void *)args[1],(unsigned)args[2]);
      break;
    case SYS_CLOSE:
      get_syscall_args(args, f->esp, 1);
      close((int)args[0]); 
      break;
    case SYS_EXEC:
      get_syscall_args(args, f->esp, 1);
      check_pointer((int *)args[0]);
      f->eax = exec((const char*)args[0]);
      break;
    case SYS_WAIT:
      get_syscall_args(args, f->esp, 1);
      f->eax = wait(args[0]);
      break;
    case SYS_SEEK:
      get_syscall_args(args, f->esp, 2);
      seek((int)args[0],(unsigned)args[1]);
      break;
    case SYS_TELL:
      get_syscall_args(args, f->esp, 1);
      f->eax = tell((int)args[0]);
      break;
  	default:
  		printf("unhandled syscall number %d\n", *sys_call);
  		thread_exit ();
  }
}

//Writes to the console if fd is 1, otherwise writes to a file
static int write(int fd, const void *buffer, unsigned size) {
  //If fd is 1, write to console
  if(fd == 1) {
    putbuf((char*)buffer, size);
    return size;
  //Otherwise, find the file in the thread's file list and write to it
  } else {
    struct file_list_data * file = find_file_data(&thread_current()->file_list,fd);
    if(!file) {
      return -1;
    } else {
      int result;
      lock_acquire(&file_sys_lock);
      result = file_write(file->file_struct, buffer, size);
      lock_release(&file_sys_lock);
      return result;
    }
  }
	return 0;
}

//Waits on a process
static int wait(pid_t pid) {
  return process_wait(pid);
}

//Prints an exit message and exits
static void exit(int status) {
  printf ("%s: exit(%d)\n", thread_current()->name, status);
	thread_exit();
	NOT_REACHED();
}

//Creates a new file
static bool create(const char * file ,unsigned initial_size) {
  if(!file) {
    exit(-1);
  }
  bool result;
  lock_acquire(&file_sys_lock);
  result = filesys_create(file, initial_size);
  lock_release(&file_sys_lock);
  return result;
}

//Removes a file
static bool remove(const char * file) {
  if(!file) {
    exit(-1);
  }
  bool result;
  lock_acquire(&file_sys_lock);
  result = filesys_remove(file);
  lock_release(&file_sys_lock);
  return result;
}

//Opens a file
static int open(const char * file) {
  lock_acquire(&file_sys_lock);
  struct file *file_struct = filesys_open(file);
  lock_release(&file_sys_lock);

  //If it wasn't able to be opened, return -1
  if(!file_struct) {
    return -1;
  //If it was, increment fd_next and add it to the thread's file_list
  } else {
    int fd = fd_next;
    fd_next++;

    //Initialize a new file_list elem
    struct file_list_data * new_file;
    new_file = malloc(sizeof(struct file_list_data));
    init_file_data(new_file,fd, file_struct,file);

    //Add it to file_list
    struct list * file_list = &thread_current()->file_list;
    list_push_back(file_list, &new_file->elem);
    return fd;
  }
}

//Closes a file
static void close(int fd) {
  struct file_list_data * file = find_file_data(&thread_current()->file_list, fd);
  //If the file wasn't found in our file_list, then it isn't open and we return -1
  if(!file) {
    exit(-1);
  //If it was, remove it from our list and close it
  } else {
    list_remove(&file->elem);
    lock_acquire(&file_sys_lock);
    file_close(file->file_struct);
    lock_release(&file_sys_lock);
  }
}

//Gets the filesize of a file
static int filesize(int fd) {
  struct file_list_data * file = find_file_data(&thread_current()->file_list, fd);
  if (!file) {
    return -1;
  } else {
    int result;
    lock_acquire(&file_sys_lock);
    result = file_length(file->file_struct);
    lock_release(&file_sys_lock);
    return result;
  }
}

//Reads size bytes from a file
static int read(int fd, void *buffer, unsigned size) {
  struct file_list_data * file = find_file_data(&thread_current()->file_list, fd);
  if (!file) {
    return -1;
  } else if(fd == 0) {
    //read from keyboard, unimplemented
    return -2;
  }
  else {
    int result;
    lock_acquire(&file_sys_lock);
    result = file_read(file->file_struct,buffer,size);
    lock_release(&file_sys_lock);
    return result;
  }
}

//Halts execution
static void halt() {
  shutdown_power_off();
}

//Executes a process given its command line. Unimplemented
static pid_t exec(const char * cmd_line) {
  return (pid_t)process_execute(cmd_line);
}

//Seeks to a given position in a file
static void 
seek(int fd, unsigned position) {
struct file_list_data * file = find_file_data(&thread_current()->file_list, fd);
  if (file) {
    lock_acquire(&file_sys_lock);
    file_seek(file->file_struct, position);
    lock_release(&file_sys_lock);
  }
}

//Returns the current position of a file
static unsigned
tell(int fd) {
  struct file_list_data * file = find_file_data(&thread_current()->file_list, fd);
  if (!file) {
    return -1;
  } else {
    int result;
    lock_acquire(&file_sys_lock);
    result = (int)file_tell(file->file_struct);
    lock_release(&file_sys_lock);
    return result;
  }
}

//Finds an element in file_list given its fd
//Returns NULL if no elements have that fd
static struct file_list_data * find_file_data(struct list * file_list, int fd) {
  if(list_empty(file_list)) {
    return NULL;
  }

  struct list_elem  *e = NULL;
  for (e = list_begin (file_list);e != list_end (file_list);e = list_next (e))
    {
      struct file_list_data *f = list_entry (e, struct file_list_data, elem);
      //If it matches, return this element
      if(f->fd == fd) {
        return f;
      }
    }

  //No matches found, return NULL
  return NULL;
}

//Gets argc number of arguments from the stack and stores them in args[]
static void
get_syscall_args (int* args, void* esp, int argc) {
  int i;
  int *addr;
  for(i=0; i<argc; i++) {
    addr = (int*) esp + i + 1;
    args[i] = *addr;
  }
}

//Verify that a user-supplied pointer is within userspace and is mapped
static void 
check_pointer(int* ptr) {
  if(ptr >= PHYS_BASE - sizeof(ptr) || ptr <= USER_BASE || !pagedir_get_page(thread_current()->pagedir, ptr)) {
    exit(-1);
  }
}
