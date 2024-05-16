#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct process
{
  int pid;                  
  int exit_code;   /*stores exit code of process*/          
  struct semaphore load_sem;  
  struct semaphore wait_sem;  
  struct list_elem elem;      
  int status; /*0 -> running process, 1 -> process completed, 
              2-> just initialized , 3 -> error encountered*/
};

/* Initialize process struct with values*/
void process_thread_init (struct thread *th);
/* Create a process, here this create just create the process struct */
struct process *process_create (struct thread *th);
/* Get the child process with given pid in the list l */
struct process *get_child_process (struct list *l, int pid);

#endif /* userprog/process.h */
