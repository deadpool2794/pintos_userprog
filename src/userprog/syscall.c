#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"


static struct lock filesys_lock;
static void syscall_handler (struct intr_frame *);
static void check_valid_ptr (const void *ptr);
static void check_valid_mem (const void *start, size_t size);
static void check_valid_str (const char *str);
static void get_args (struct intr_frame *f, void *args[], int argc);

struct file_list_elem
{
  int fd; 
  struct file *file;
  struct list_elem elem;
};

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f)
{
  
  check_valid_mem (f->esp, sizeof (void *));
  void *args[3];
  switch (*(int *)f->esp)
    {
    case SYS_HALT:
      {
        halt_systemcall_handler ();
        break;
      }
    case SYS_EXIT:
      { 
        get_args (f, args, 1);
        exit_systemcall_handler (*(int *)args[0]);
        break;
      }
    case SYS_EXEC:
      {
        get_args (f, args, 1);
        f->eax = exec_systemcall_handler (*(const char **)args[0]);
        break;
      }
    case SYS_WAIT:
      {
        get_args (f, args, 1);
        f->eax = wait_systemcall_handler (*(int *)args[0]);
        break;
      }
    case SYS_CREATE:
      {
        get_args (f, args, 2);
        f->eax
            = create_systemcall_handler (*(const char **)args[0], *(unsigned *)args[1]);
        break;
      }
    case SYS_REMOVE:
      {
        
        get_args (f, args, 1);
        f->eax = remove_systemcall_handler (*(const char **)args[0]);
        break;
      }
    case SYS_OPEN:
      {
        get_args (f, args, 1);
        f->eax = open_systemcall_handler (*(const char **)args[0]);
        break;
      }
    case SYS_FILESIZE:
      {
        get_args (f, args, 1);
        f->eax = filesize_systemcall_handler (*(int *)args[0]);
        break;
      }
    case SYS_READ:
      {
        get_args (f, args, 3);
        f->eax = read_systemcall_handler (*(int *)args[0], *(void **)args[1],
                               *(unsigned *)args[2]);
        break;
      }
    case SYS_WRITE:
      {
        get_args (f, args, 3);
        f->eax = write_systemcall_handler (*(int *)args[0], *(const void **)args[1],
                                *(unsigned *)args[2]);
        break;
      }
    case SYS_SEEK:
      {
        get_args (f, args, 2);
        seek_systemcall_handler (*(int *)args[0], *(unsigned *)args[1]);
        break;
      }
    case SYS_TELL:
      {
        get_args (f, args, 1);
        f->eax = tell_systemcall_handler (*(int *)args[0]);
        break;
      }
    case SYS_CLOSE:
      {
        get_args (f, args, 1);
        close_systemcall_handler (*(int *)args[0]);
        break;
      }
    default:
      {
        exit_systemcall_handler (-1);
        break;
      }
    }
}

static void
check_valid_ptr (const void *ptr)
{
  if (!ptr || !is_user_vaddr (ptr) || ptr < (void *)0x08048000
      || !pagedir_get_page (thread_current ()->pagedir, ptr))
    {
      exit_systemcall_handler (-1);
    }
}


static void
check_valid_mem (const void *start, size_t size)
{
  const char *ptr = start;
  size_t i;
  
  for (i = 0; i < size; ++i)
    {
      check_valid_ptr ((const void *)ptr++);
    }
}


static void
check_valid_str (const char *str)
{

  check_valid_ptr (str);
  while (*str)
    check_valid_ptr (++str);
}


static void
get_args (struct intr_frame *f, void *args[], int argc)
{
  int i;
  for (i = 0; i < argc; ++i)
    {
      void *ptr = ((char *)f->esp) + (i + 1) * 4;
      check_valid_mem (ptr, sizeof (void *));
      args[i] = ptr;
    }
}

void
halt_systemcall_handler ()
{
  shutdown_power_off ();
}

void
exit_systemcall_handler (int status)
{
  struct thread *cur = thread_current ();
  while (!list_empty (&cur->active_files))
    {
      struct file_list_elem *f = list_entry (list_back (&cur->active_files),
                                             struct file_list_elem, elem);
      close_systemcall_handler (f->fd);
    }
  cur->process->exit_code = status;
  thread_exit ();
}

int
exec_systemcall_handler (const char *cmd_line)
{
  check_valid_str (cmd_line);
  
  
  lock_acquire (&filesys_lock);
  int pid = process_execute (cmd_line);
  lock_release (&filesys_lock);
  
  if (pid == TID_ERROR)
    return -1;
  struct thread *child = get_thread (pid);
  
  if (!child)
    return -1;
  struct process *child_process = child->process;
  sem_down (&child_process->load_sem);
  bool success = child_process->status == 0
                 || child_process->status == 1;
  if (!success)
    {
      sem_down (&child_process->wait_sem);
      list_remove (&child_process->elem);
      free (child_process);
      return -1;
    }
  return pid;
}

int
wait_systemcall_handler (int pid)
{
  return process_wait (pid);
}

struct file_list_elem *
get_file (int fd)
{
  struct list_elem *e;
  struct list *open_file_list = &thread_current ()->active_files;
  
  for (e = list_begin (open_file_list); e != list_end (open_file_list);
       e = list_next (e))
    {
      struct file_list_elem *f = list_entry (e, struct file_list_elem, elem);
      if (f->fd == fd)
        return f;
    }
  
  exit_systemcall_handler (-1);
  return NULL;
}

bool
create_systemcall_handler (const char *file, unsigned initial_size)
{
  check_valid_str (file);
  lock_acquire (&filesys_lock);
  bool success = filesys_create (file, initial_size);
  lock_release (&filesys_lock);
  return success;
}

bool
remove_systemcall_handler (const char *file)
{
  check_valid_str (file);
  lock_acquire (&filesys_lock);
  bool success = filesys_remove (file);
  lock_release (&filesys_lock);
  return success;
}

int
open_systemcall_handler (const char *file)
{
  check_valid_str (file);
  lock_acquire (&filesys_lock);
  struct file *f = filesys_open (file);
  lock_release (&filesys_lock);
  if (!f)
    return -1;
  struct thread *cur = thread_current ();
  struct file_list_elem *open_file = malloc (sizeof (struct file_list_elem));
  if (!open_file)
    return -1;
  open_file->fd = cur->fd++;
  open_file->file = f;
  list_ins_back (&cur->active_files, &open_file->elem);
  return open_file->fd;
}

int
filesize_systemcall_handler (int fd)
{
  struct file_list_elem *f = get_file (fd);
  
  lock_acquire (&filesys_lock);
  int len = file_length (f->file);
  lock_release (&filesys_lock);
  return len;
}

int
read_systemcall_handler (int fd, void *buffer, unsigned size)
{
  
  check_valid_mem (buffer, size);
  if (fd == STDIN_FILENO)
    return input_getc ();
  
  if (fd == STDOUT_FILENO)
    exit_systemcall_handler (-1);
  struct file_list_elem *f = get_file (fd);
  
  lock_acquire (&filesys_lock);
  
  int len = file_read (f->file, buffer, size);
  lock_release (&filesys_lock);
  return len;
}

int
write_systemcall_handler (int fd, const void *buffer, unsigned size)
{
  
  check_valid_mem (buffer, size);
  if (fd == STDOUT_FILENO)
    {
      putbuf ((const char *)buffer, size);
      return size;
    }
  
  if (fd == STDIN_FILENO)
    exit_systemcall_handler (-1);

  struct file_list_elem *f = get_file (fd);
  
  lock_acquire (&filesys_lock);
  
  int len = file_write (f->file, buffer, size);
  lock_release (&filesys_lock);
  return len;
}

void
seek_systemcall_handler (int fd, unsigned position)
{
  struct file_list_elem *f = get_file (fd);
  
  lock_acquire (&filesys_lock);
  file_seek (f->file, position);
  lock_release (&filesys_lock);
}

unsigned
tell_systemcall_handler (int fd)
{
  struct file_list_elem *f = get_file (fd);
  
  lock_acquire (&filesys_lock);
  int pos = file_tell (f->file);
  lock_release (&filesys_lock);
  return pos;
}

void
close_systemcall_handler (int fd)
{
  struct file_list_elem *f = get_file (fd);
  
  lock_acquire (&filesys_lock);
  file_close (f->file);
  lock_release (&filesys_lock);
  list_remove (&f->elem);
  
  free (f);
}