#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#define NUMBER_OF_SYSTEM_CALLS 15   /* Total number of system calls there are. */
#define INITIAL_FID 2               /* Starting fid when a file is opened as 0 and 1 are reserved. */
#define MAX_BUFFER_WRITE_SIZE 500   /* Maximum number of bytes that can be written to teh buffer at once. */

typedef int pid_t;

void syscall_init (void);
struct lock* get_file_lock(void);
void system_exit (int status);

#endif /* USERPROG_SYSCALL_H */
