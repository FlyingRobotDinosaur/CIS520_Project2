#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "lib/kernel/list.h"
#include "filesys/inode.h"
#include "devices/shutdown.h"
#include "threads/synch.h"
#include "devices/input.h"



static void syscall_handler (struct intr_frame *);
struct thread* child;
struct thread* cur;
struct file* file;
char* name;
unsigned int size;
int fd;
int status;
pid_t pid;
char* cmd_line;
uint8_t* bufferR;
char *bufferw;
unsigned int i;
unsigned int p;

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
    case SYS_EXIT:
	cur=thread_current();
	status = *(int *)(ptr+1);

	printf("%s: exit(%d)\n", cur->name, status);
        thread_exit ();
    break;
    case SYS_EXEC:
	cmd_line = (char *)(ptr + 1);
	pid = process_execute(cmd_line);
	child = getChild(pid);
	if(!child)
	{
		f->eax = -1;
		break;
	}
	if(child->load == 0)
	{	
		sema_down(&child->loaded);
	}
	if(child->load == -1)
	{
		list_remove(&child->childelem);
		free(child);	
		f->eax = -1;
		break;
	}
	
	f->eax = pid;
    break;
    case SYS_WAIT:
	pid =  (pid_t) * (ptr +1);
	f->eax = process_wait(pid);
    break;
    case SYS_CREATE:
	lock_acquire(&fs_lock);
	name = (char *)(ptr+1);
	size = *(ptr+2);
		
	if(!name)
	{
		f->eax = (-1);
		break;
	}	
	
	
	f->eax = filesys_create(name,size);
	
    break;
    case SYS_REMOVE:

	name = (char *)(ptr+1);
	if(!name)
	{
		f->eax = false;
		
		break;
	}
	
	else
		lock_acquire(&fs_lock);
		f->eax = filesys_remove(name);
		lock_release(&fs_lock);
    break;
    case SYS_OPEN:
	lock_acquire(&fs_lock);
	name = (char *)(ptr + 1);
	
	if(!name)
	{ 	lock_release(&fs_lock);
		f->eax = -1;
		break;
	}
	
	file = filesys_open(name);
	
	if(!file)
	{
		lock_release(&fs_lock);
		f->eax = -1;
		break;
	}
	fd = addFile(file);
	f->eax = fd;
	lock_release(&fs_lock);	
    break;
    case SYS_FILESIZE:
	fd = *(ptr + 1);
	file = getFile(fd);
	if (!file){ f->eax = -1;}
	else f->eax = file_length(file);
    break;
    case SYS_READ:
	// check for valid pointers???
	fd = *(ptr + 1);
	file = getFile(fd);
	bufferR =  (uint8_t *)(ptr+2);
	size = *(ptr +3);
	
	if (fd == STDIN_FILENO)
	{
		for (i = 0; i < size; i++)
		{
	 	 *(uint8_t *)(bufferR + i) = input_getc();
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
			f->eax= file_read (file, bufferR, size);
			lock_release(&fs_lock);
		}
	}
    break;
    case SYS_WRITE:
	fd =  *(ptr+1);
	file = getFile(fd);
	bufferw = (char *)(ptr+2);
	size = *(ptr+3);
	if (fd == STDOUT_FILENO) 
              putbuf (bufferw, size);
	else if (fd == STDIN_FILENO)
		{f->eax = -1; break;}
	else	
	{
		if (!file) 
			{f->eax = -1; break;} 
		else
		{
			lock_acquire(&fs_lock);
			f->eax= file_write (file, bufferw, size);
			lock_release(&fs_lock);
		}
	}
    break;
    case SYS_SEEK:
	lock_acquire(&fs_lock);
	fd = *(ptr +1);
	p = *(ptr+2);
	file = getFile(fd);
	
	if(!file)
	{
		f->eax = -1;
		lock_release(&fs_lock);	
		break;
	}
	else
		file_seek(file, p);
		f->eax = 0;
		lock_release(&fs_lock);

    break;
    case SYS_TELL:
	lock_acquire(&fs_lock);
	fd = *(ptr+1);
	file = getFile(fd);
	if(!file)
	{
		f->eax= -1;
		lock_release(&fs_lock);
	}
	else 
		f->eax = file_tell(file);
		lock_release(&fs_lock);

    break;
    case SYS_CLOSE:
	lock_acquire(&fs_lock);
	fd = (int)*(ptr+1);
	file = getFile(fd);
	if (!file)
	{
		f->eax= -1;
		lock_release(&fs_lock);
		break;
	}
	else
	{
  		closeFile(fd);
		f->eax = 0;
 		lock_release(&fs_lock);
	}
    break;
    default:
    thread_exit();
  }
}



struct thread* getChild(int pid)
{
	struct list_elem *e;
	struct thread* c = thread_current();
	
	for (e = list_begin (&c->children); e != list_end (&c->children); e = list_next (e))
  	{
	struct thread *childstatus = list_entry(e, struct thread, childelem);
	if (childstatus->tid == pid)
        return childstatus;
  	}
  return NULL;
}

void removeChildren(void)
{
	struct thread *c = thread_current();
	struct list_elem *next;
	struct list_elem *e = list_begin(&c->children);
	while (e != list_end (&c->children))
	{
		next = list_next(e);
		struct thread *t = list_entry (e, struct thread, childelem);
		list_remove(&t->childelem);
		free(t);
		e = next;
	}
}


