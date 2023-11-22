#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdbool.h>
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "vm/page.h"
#include "vm/share.h"
#include "threads/vaddr.h"
#include "threads/pte.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"

/* Number of page faults processed. */
static long long page_fault_cnt;
// number of bytes that stack has grown by
static unsigned total_stack_growth = PGSIZE;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);
void finish(struct intr_frame *f, bool user);

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */

  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill, "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill, "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill, "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      thread_current()->return_status = -1; /* Changes status of thread to -1, so it is known the exit is erroneous. */
      thread_exit (); 

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      /* Some other code segment?  
         Shouldn't happen.  Panic the kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      PANIC ("Kernel bug - this shouldn't be possible!");
    }
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to task 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f) 
{
   bool user;         /* True: access by user, false: access by kernel. */
   void *fault_addr;  /* Fault address. */

   /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
   asm ("movl %%cr2, %0" : "=r" (fault_addr));

   /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
   intr_enable ();

   /* Count page faults. */
   page_fault_cnt++;

   /* Determine cause. */
   user = (f->error_code & PF_U) != 0;
   bool write = (f->error_code & PF_W) != 0;
   bool not_present = (f->error_code & PF_P) == 0;
   struct thread *t = thread_current();
   void *unrounded_fault_addr = fault_addr;
   fault_addr = pg_round_down(fault_addr);

   if (!user && !is_user_vaddr(fault_addr))
       finish(f, user);

   if (fault_addr == NULL || !is_user_vaddr(fault_addr))
       finish(f, user);

   struct s_page *page = spt_get_element(t->spt, fault_addr);

    /* If the page is an executable read only page, which already exists in the share table, we pass a pointer in the page so
       that it isnt duplicated, and instead multiple processes can own the same page. If it doesn't exist, we add the page to 
       the share table is it is executable and read only, so that any future pages can share this. */
   if (page != NULL) {
      if ((write && !page->writeable) || !page->valid)
          finish(f, true);
      if ((!page->writeable) && page->mmapped && (page->file != NULL)) {
         struct s_page *sharedPage = share_table_get_elem(page->file, fault_addr);
         if (sharedPage != NULL)
            page = sharedPage;
         else {
            pin_page(page->physical_page);
            share_table_insert(page);
         }
      }
      page->physical_page = get_frame(PAL_USER);
      struct frame_element *frame = find_frame(page->physical_page);
      
      frame->page = page->vaddr;
      if (!page_load(page))
          finish(f, true);
   }
   /* If the required page isn't an executable read only page already in the page table, then we check if there is stack space,
      and grow the stack if required. */
   else if (within_stack_space(PTE_ADDR & (unsigned) f->esp, unrounded_fault_addr) && 
        !out_of_stack_space(PTE_ADDR & (unsigned) f->esp)) {
      page = grow_stack(fault_addr);
      page->writeable = true;
      spt_insert(thread_current()->spt, page);
   }
   else {
       finish(f, user || not_present);
   }
}

/* Copies the old eax value in eip and sets eax before exiting. */
void finish(struct intr_frame *f, bool user)
{
    if (!user) {
        f->eip = (void *) f->eax;
        f->eax = 0xffffffff;
    }
    system_exit(ERROR_RET);
}

/* Checks if a particular access is a stack access */
bool
within_stack_space(uint32_t stack_pointer, void *address)
{
  return ((unsigned) address >= stack_pointer - 32) && is_user_vaddr(address);
}

/* Checks if we have reached the maximum stack size of 8MB */
bool
out_of_stack_space(unsigned address)
{
    return ((unsigned) PHYS_BASE - address) > MAX_STACK_SIZE;
}

/* Grows stack by allocating a new page at the given address */
struct s_page*
grow_stack (void *fault_address)
{
   total_stack_growth += PGSIZE;
   struct s_page *page = new_page(fault_address);
   return page;
}

