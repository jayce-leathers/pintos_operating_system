#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);

static int write(int fd, const void *buffer, unsigned size);
static void exit(int status);
static void halt(void);
const int MAX_ARGS = 128;
const int USER_BASE = 0x08048000;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
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
check_pointer(int* ptr) {
  if(!is_user_vaddr(ptr) || ptr < USER_BASE) {
    exit(-1);
  }
}

static void
syscall_handler (struct intr_frame *f) 
{
  int *sys_call; //syscall number
  sys_call = (int*)f->esp;

  check_pointer(sys_call);

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
	//printf("system call: sys_exit() with status %d\n", status);
  printf ("%s: exit(%d)\n", thread_current()->name, status);
	thread_exit();
	NOT_REACHED();
	//want to return exit status, so thread can wait on it and get exit status
	//save it in a field in struct thread
}

static void halt() {
  shutdown_power_off();
}