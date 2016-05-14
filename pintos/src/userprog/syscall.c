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

//file methods
// static int find_fd(struct list * file_list, char * name);
// static char * find_file_name(struct list *file_list, int fd);
// static struct file * find_file(struct list *file_list, int fd);

static struct file_list_data * find_file_data(struct list * file_list, int fd); 

static int fd_next;
const int MAX_ARGS = 128;
const int USER_BASE = 0x08048000;


static void init_file_data(struct file_list_data * f, int fd, struct file * file_struct, const char * file_name) {
  f->fd = fd;
  f->file_struct = file_struct;
  f->file_name = file_name;
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  fd_next = 2;
}

static void
get_syscall_args (int* args, void* esp, int argc) {
  int i;
  int *addr;
  for(i=0; i<argc; i++) {
    addr = (int*) esp + i + 1;
    args[i] = *addr;
  }
}

static void 
check_pointer_no_ret(int* ptr) {
  //printf("cp ptr: %p\n", ptr);
  if(ptr >= PHYS_BASE - sizeof(ptr) || ptr < USER_BASE || !pagedir_get_page(thread_current()->pagedir, ptr)) {
    // if(ptr >= PHYS_BASE - sizeof(ptr))
    //   printf("failed pointer, too high: %p\n", ptr);

    // if(ptr < USER_BASE)
    //   printf("failed pointer, too low: %p\n", ptr);
    exit(-1);
  }
}

// static bool check_pointer(int* ptr) {
//   //printf("cp ptr: %p\n", ptr);
//   bool success;
//   if(ptr >= PHYS_BASE - sizeof(ptr) || ptr < USER_BASE || !pagedir_get_page(thread_current()->pagedir, ptr)) {
//     // if(ptr >= PHYS_BASE - sizeof(ptr))
//     //   printf("failed pointer, too high: %p\n", ptr);

//     // if(ptr < USER_BASE)
//     //   printf("failed pointer, too low: %p\n", ptr);
//     success = 0;
//   } else {
//     success = 1;
//   }
//   return success;
// }

static void
syscall_handler (struct intr_frame *f) 
{
  int *sys_call; //syscall number
  check_pointer_no_ret(f->esp);
  sys_call = (int*)f->esp;
  check_pointer_no_ret(sys_call);

  int args[MAX_ARGS];

  switch(*sys_call) {
  	case SYS_WRITE:
      get_syscall_args(args, f->esp, 3);
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
      check_pointer_no_ret((int *)args[0]);
      // check_pointer_no_ret(args[1]);
      f->eax = create((const char*)args[0], args[1]);
      break;
    case SYS_REMOVE:
      get_syscall_args(args, f->esp, 1);
      check_pointer_no_ret((int *)args[0]);
      f->eax = remove((const char*)args[0]);
      break;
    case SYS_OPEN:
      get_syscall_args(args, f->esp, 1);
      check_pointer_no_ret((int *)args[0]);
      f->eax = open((const char*)args[0]);
      break;
    case SYS_FILESIZE:
      get_syscall_args(args, f->esp, 1);
      f->eax = filesize((int)args[0]);
      break;
    case SYS_READ:
      get_syscall_args(args, f->esp, 3);
      check_pointer_no_ret((int *)args[1]);
      f->eax = read((int)args[0],(void *)args[1],(unsigned)args[2]);
      break;
    case SYS_CLOSE:
      get_syscall_args(args, f->esp, 1);
      close((int)args[0]); 
      break;
    // case SYS_WAIT:
    //   get_syscall_args(args, f->esp, 1);
    //   f->eax = wait(args[0]);
    //   break;
  	default:
  		printf("unhandled syscall number %d\n", *sys_call);
  		thread_exit ();
  }
}


static int write(int fd, const void *buffer, unsigned size) {
	//printf("fd: %i, buffer: %p, size: %i\n", fd, buffer, size);
  if(fd == 1) {
    putbuf((char*)buffer, size);
    return size;
  } else {
    printf("system call: sys_write() (not fd 1)\n");
  }
	return 0;
}

static void exit(int status) {
  printf ("%s: exit(%d)\n", thread_current()->name, status);
	thread_exit();
	NOT_REACHED();
	//want to return exit status, so thread can wait on it and get exit status
	//save it in a field in struct thread
}

// static pid_t exec(const char *cmd_line) {

// }

static bool create(const char * file ,unsigned initial_size) {
  //printf("file: %p\n", file);
  //check_pointer(file);
  //printf("file:<%s>\n", file);
  //*file == "" ||  initial_size <= 0 ||  strlen(file) > 15
  if(!file) {
    exit(-1);
  }
  return filesys_create(file, initial_size);
}

static bool remove(const char * file) {
  if(!file) {
    exit(-1);
  }
  return filesys_remove(file);
}

static int open(const char * file) {
  struct file *file_struct = filesys_open(file);
  if(!file_struct) {
    return -1;
  } else {
    int fd = fd_next;
    fd_next++;
    struct file_list_data * new_file;
    new_file = malloc(sizeof(struct file_list_data));
    init_file_data(new_file,fd, file_struct,file);
    struct list file_list = thread_current()->file_list;
    list_push_back(&file_list, &new_file->elem);
    // printf("opened file:%i\n",fd);
    return fd;
  }
}
static void close(int fd) {
  struct file_list_data * file = find_file_data(&thread_current()->file_list, fd);
  if(!file) {
    // printf("file is null\n");
  } else {
    // printf("list size = %i\n", list_size(&thread_current()->file_list));
    list_remove(&file->elem);
    // printf("list size = %i\n", list_size(&thread_current()->file_list));
    // printf("removed file:%i name = %s\n",fd,file->file_name);
    file_close(file->file_struct);
    // printf("closed file:%i\n",fd);
    free(file);
  }
}

static int filesize(int fd) {
  struct file_list_data * file = find_file_data(&thread_current()->file_list, fd);
  if (!file) {
    return -1;
  } else {
    return file_length(file->file_struct);
  }
}

static int read(int fd, void *buffer, unsigned size) {
  // printf("trying to read from file:%i\n",fd);
  struct file_list_data * file = find_file_data(&thread_current()->file_list, fd);
  if (!file) {
    return -1;
  } else if(fd == 0) {
    //read from keyboard
    return -2;
  }
  else {
    // printf("read from file:%i\n",fd);
    return file_read(file->file_struct,buffer,size);
  }
}



static void halt() {
  shutdown_power_off();
}

static struct file_list_data * find_file_data(struct list * file_list, int fd) {
  if(list_empty(file_list)) {
    // printf("list is empty\n");
    return NULL;
  }
  // printf("list not empty\n");
  struct list_elem  *e;
  for (e = list_begin (file_list);e != list_end (file_list);e = list_next (e))
    {
      struct file_list_data *f = list_entry (e, struct file_list_data, elem);
      if(f->fd == fd) {
        return f;
      }
    }
    return NULL;
}

