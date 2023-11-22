#ifndef USERPROG_EXCEPTION_H
#define USERPROG_EXCEPTION_H

/* Page fault error code bits that describe the cause of the exception.  */
#define PF_P 0x1    /* 0: not-present page. 1: access rights violation. */
#define PF_W 0x2    /* 0: read, 1: write. */
#define PF_U 0x4    /* 0: kernel, 1: user process. */

#define MAX_STACK_SIZE (1<<23)

#include <hash.h>
#include "vm/frame.h"

void exception_init (void);
void exception_print_stats (void);
bool within_stack_space(uint32_t stack_pointer, void *address);
bool out_of_stack_space(unsigned address);
struct s_page* grow_stack (void *fault_address);

#endif /* USERPROG_EXCEPTION_H */
