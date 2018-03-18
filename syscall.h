#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H


#include "threads/synch.h"

#include "threads/thread.h"
struct lock fs_lock;

void removeChildren(void);
struct thread* getChild(int pid);

void syscall_init (void);

#endif /* userprog/syscall.h */
