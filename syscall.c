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
#include "devices/shutdown.h"
#include "threads/synch.h"

static struct lock fs_lock;

struct fdescriptor {
  struct file *file;
  int fd;
  struct list_elem elem;
};


int addFile (struct file *f);
struct file* getFile (int fd);
static void syscall_handler (struct intr_frame *);
void closeFile(int fd);
struct thread* getChild(int pid);

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
	struct thread* cur=thread_current();
	int status = *(int *)(ptr+1);

	printf("%s: exit(%d)\n", cur->name, status);
        thread_exit ();
    break;
    case SYS_EXEC:
	char* cmd_line = *(ptr + 1);
	pid_t pid = process_execute(cmd_line);
	struct thread* child = getChild(pid);
	if(!child)
	{
		f->eax = -1;
		break;
	}
	if(child->load == 0)
	{	
		sema_down(&cp->loaded);
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
	pid_t pid =  (pid_t) * (ptr +1)
	f->eax = process_wait(pid)
    break;
    case SYS_CREATE:
	lock_acquire(&fs_lock);
	char* name = (ptr+1);
	unsigned size = *(ptr+2);
		
	if(!name)
	{
		sys_exit(-1);
		break;
	}	
	if(!valid(name))
	{
		sys_exit(-1);
	}
	
	f->eax = filesys_create(name,size);
	
    break;
    case SYS_REMOVE:

	char* name = (char *)(ptr+1);
	if(!name)
	{
		f->eax = false;
		sys_exit(-1);
		break;
	}
	if(!valid (name))
	{
		sys_exit(-1);
		break;	
	}
	else
		lock_acquire(&fs_lock);
		f->eax = filesys_remove(name);
		lock_release(&fs_lock);
    break;
    case SYS_OPEN:
	lock_acquire(&fs_lock);
	char* name = *(ptr + 1);
	int fd;
	if(!name)
	{ 	lock_release(&fs_lock);
		f->eax = -1;
		break;
	}
	else if (!valid(name))
	{lock_release(&fs_lock); sys_exit(-1);}

	struct file *file = filesys_open(name);
	
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
	int fd = *(ptr + 1);
	struct file* file = getFile(fd);
	if (!file){ f->eax = -1;}
	else f->eax = file_length(file);
    break;
    case SYS_READ:
	// check for valid pointers???
	int fd = *(ptr + 1);
	struct file* file = getFile(fd);
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
    case SYS_WRITE:
	int fd =  *(ptr+1);
	struct file* file = getFile(fd);
	char *buffer = *(ptr+2);
	unsigned int size = *(ptr+3);
	if (fd == STDOUT_FILENO) 
              putbuf (buffer, size);
	else if (fd = STDIN_FILENO)
		{f->eax = -1; break;}
	else	
	{
		if (!file) 
			{f->eax = -1; break;} 
		else
		{
			lock_acquire(&fs_lock);
			f->eax= file_write (file, buffer, size);
			lock_release(&fs_lock);
		}
	}
    break;
    case SYS_SEEK:
	lock_acquire(&fs_lock);
	int fd = *(ptr +1);
	unsigned int p = *(ptr+2);
	struct file* file = getFile(fd);
	
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
	int fd = *(ptr+1);
	struct file* file = getFile(fd);
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
	int fd = (int)*(ptr+1);
	struct file* file = getFile(fd);
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

void removeChildren(void)
{
	struct thread cur* = thread_current();
	struct list_elem *next;
	struct list_elem *e = list_begin(&cur->children);
	while (e != list_end (&cur->children);
	{
		next = list_next(e);
		struct thread *t = list_entry (e, struct thread, childelem);
		list_remove(&t->childelem);
		free(t);
		e = next;
	}
}

struct file* getFile(int fd)
{
  struct list_elem *e;
  struct thread* t = thread_current();

  for (e = list_begin (&t->fds); e != list_end (&t->fds); e = list_next (e))
  {
     struct fdescriptor *f = list_entry(e, struct fdescriptor, elem);
     if (f->fd == fd)
        return f->file;
  }

  return NULL;
}

int addFile(struct file *fi)
{
	struct fdescriptor *f = malloc(sizeof(struct fdescriptor));
	if(!f){return -1;}
	f->file = fi;
	f->fd = thread_current()->fd;
	thread_current()->fd++;
	list_push_back(&thread_current()->fds, &f->elem);
	return f->fd;
}

void closeFile(int fd)
{
	struct thread *t = thread_current();
	struct list_elem *next;
	struct list_elem *e = list_begin(&t->fds);
	while (e != list_end (&t->fds))
	{
		next = list_next(e);
		struct fdescriptor *f = list_entry(e, struct fdescriptor, elem);
		if( fd == f->fd || fd == -1)
		{
			file_close(f->file);
			list_remove(&f->elem);
			free(f);
		
		}
		e = next;
	}


}

}
