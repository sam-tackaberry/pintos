#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"


#define EXIT_SUCCESS 0
#define ERROR_RET -1
#define INT_SIZE 4
#define MAX_STACK_POINTERS (PGSIZE / 6)
#define MAX_STACK 100 * PGSIZE
typedef int tid_t;

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
bool install_page (void *upage, void *kpage, bool writable);

#endif /* USERPROG_PROCESS_H */
