#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/pagedir.h"
#include "threads/vaddr.h"
#include "lib/kernel/list.h"
#include "filesys/inode.h"
static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&fs_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{


uint32_t* ptr = f->esp;
int callNum = (int) f->esp;

  switch(callNum){
    case SYS_HALT:
      shutdown_power_off ();
    break;
    case SYS_EXIT
	struct thread* cur=thread_current();
	int status = *(int *)(ptr+1);
	printf("%s: exit(%d)\n", cur->name, status);
        thread_exit ();
    break;
    case SYS_EXEC

    break;
    case SYS_WAIT
	pid_t pid =  (pid_t) * (ptr +1)
	f->eax = process_wait(pid)
    break;
    case SYS_CREATE

    break;
    case SYS_REMOVE

    break;
    case SYS_OPEN

    break;
    case SYS_FILESIZE
	int fd = *(ptr + 1);
	struct file* file = getFile(fd);
	if (!file){ f->eax = -1;}
	else f->eax = file_length(file);
    break;
    case SYS_READ
	// check for valid pointers???
	struct file* file = getFile(fd);
	int fd = *(ptr + 1);
	uint8_t* buffer = *(ptr+2);
	unsigned int size = *(ptr +3);
	unsigned int i;
	if (fd == STDIN_FILENO)
	{
		for (i = 0; i < size; i++)
		{
	 	 *(uint8_t *)(buffer + i) = input_getc();
		}
	 f->eax = size;
	}
	else if (fd == STDOUT_FILENO)
		{f->eax = -1; break;}
	else
	{
		if (!file)
			{f->eax = -1; break;}
		else 
		{
			lock_acquire(&fs_lock);
			f->eax= file_read (file, buffer, size);
			lock_release(&fs_lock);
		}
	}
    break;
    case SYS_WRITE
	struct file* file = getFile(fd);
	int fd =  *(ptr+1);
	char *buffer = *(ptr+2);
	unsigned int size = *(ptr+3);
	if (fd == STDOUT_FILENO) 
              putbuf (buffer, size);
	else if (fd = STDIN_FILENO)
		{f->eax = -1; break;}		//ERROR
	else	
	{
		if (!file) 
			{f->eax = -1; break;} //ERROR
		else
		{
			lock_acquire(&fs_lock);
			f->eax= file_write (file, buffer, size);
			lock_release(&fs_lock);
		}
	}
    break;
    case SYS_SEEK

    break;
    case SYS_TELL

    break;
    case SYS_CLOSE

    break;
    default
    thread_exit();
  }
}

static void * vaddRead(void *vaddr){
    if(vaddr != NULL && is_user_vaddr(vaddr)){
      void *paddr = pagedir_get_page(active_pd(), vaddr);
      if(paddr != NULL)
        return paddr;
    }
    return (void *) -1;
  }

struct thread* getChild(int pid)
{
	struct list_elem *e;
	struct thread* t = thread_current();
	
	for (e = list_begin (&t->children); e != list_end (&t->children); e = list_next (e))
  	{
	struct thread *childstatus = list_entry(e, struct wait_status, childelem);
	if (childstatus->tid == pid)
        return childstatus;
  	}
  return NULL;
}



struct file* getFile(int fd)
{
  struct list_elem *e;
  struct thread* t = thread_current();

  for (e = list_begin (&t->fds); e != list_end (&t->fds); e = list_next (e))
  {
     struct file *f = list_entry(e, struct file, open_file_elem);
     if (f->fd == fd)
        return f;
  }

  return NULL;
}


}
