#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

static int sys_write(int fd, const void *buffer, unsigned size);
static void exit(int status);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int *sys_call; //syscall number
  int* status;
  sys_call = (int*)f->esp;

  switch(*sys_call) {
  	case SYS_WRITE:
  		f->eax = sys_write(1, NULL, 0);
  		break;
  	case SYS_EXIT:
  		status = (int*)f->esp+1;
  		exit(*status);
  		break;
  	default:
  		printf("unhandled syscall number %d\n", *sys_call);
  		thread_exit ();
  }
}

static int sys_write(int fd UNUSED, const void *buffer UNUSED, unsigned size UNUSED) {
	printf("system call: sys_write()\n");
	return 0;
}

static void exit(int status) {
	printf("system call: sys_exit() with status %d\n", status);
	thread_exit();
	NOT_REACHED();
	//want to return exit status, so thread can wait on it and get exit status
	//save it in a field in struct thread
}