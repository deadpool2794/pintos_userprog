#ifndef USERPROG_H_systemcall_handler
#define USERPROG_H_systemcall_handler
#include <stdbool.h>

void syscall_init (void);

int write_systemcall_handler (int fd, const void *buffer, unsigned size);
void halt_systemcall_handler (void);
int exec_systemcall_handler (const char *cmd_line);
void seek_systemcall_handler (int fd, unsigned position);
int open_systemcall_handler (const char *file);
bool create_systemcall_handler (const char *file, unsigned initial_size);
void close_systemcall_handler (int fd);
bool remove_systemcall_handler (const char *file);
int filesize_systemcall_handler (int fd);
void exit_systemcall_handler (int status);
unsigned tell_systemcall_handler (int fd);
int read_systemcall_handler (int fd, void *buffer, unsigned size);
int wait_systemcall_handler (int pid);

#endif 

