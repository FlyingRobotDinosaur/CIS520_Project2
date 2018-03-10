#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "threads/pagedir.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  int callNum = (int) f->eax;

  swith(callNum){
    case SYS_HALT:
      shutdown_power_off ();
    break;
    case SYS_EXIT
      thread_exit ();
    break;
    case SYS_EXEC

    break;
    case SYS_WAIT

    break;
    case SYS_CREATE

    break;
    case SYS_REMOVE

    break;
    case SYS_OPEN

    break;
    case SYS_FILESIZE

    break;
    case SYS_READ

    break;
    case SYS_WRITE

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
