#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "vm/frame.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/syscall.h"
#include "vm/page.h"
#include "vm/mmap.h"

static thread_func start_process NO_RETURN;
static void sema_up_waiters(struct thread *cur);
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */

tid_t
process_execute (const char *cmdLine)
{
    /* Used as a copy of the command line to prevent race conditions*/
    char* cl_copy = palloc_get_page(0);
    if (cl_copy == NULL)
        return TID_ERROR;

    /*Tokenizes only the first argument to get filename*/
    int i = 0;
    while (! (cmdLine[i] == ' ' || cmdLine[i] == '\0')) 
      i++;
    if (cmdLine[i] == ' ')
      i--;
    char* file_name = malloc(i + 1);
    

    tid_t tid;

    if (file_name == NULL) {
        palloc_free_page(cl_copy);
        return TID_ERROR;
    }

    /* Make a copy of file_name and cl_copy.
       Otherwise there's a race between the caller and load(). */
    strlcpy (cl_copy, cmdLine, PGSIZE);
    strlcpy (file_name, cmdLine, i + 2);

    /* Create a new thread to execute FILE_NAME. */
    tid = thread_create (file_name,
            PRI_DEFAULT, start_process, cl_copy);

    free(file_name);
    if (tid == TID_ERROR) {
      palloc_free_page (cl_copy);
      return tid;
    }

    struct thread *t = thread_with_tid (tid);

    /*makes the current thread wait the thread with tid to execute.*/
    sema_down (&t->wait_sema);

    /*If t has encountered an error, return TID_ERROR*/
    if (t->return_status == ERROR_RET)
      return TID_ERROR;  
    return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_and_args)
{
  char *file_name = thread_current()->name;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  /*Allow current thread to start its process*/
  sema_up(&thread_current()->wait_sema);

  /* If load failed, quit. */
  if (!success) {
    palloc_free_page(file_name_and_args);
    //remove_frame(file_name_and_args);
    thread_current()->return_status = ERROR_RET;
    thread_exit();
  }

  /* Allocate array of stack pointers to hold each of the arguments. */
  uint32_t stack_pointers[MAX_STACK_POINTERS];

  char *save_ptr; /* Used for strtok_r as a context parameter. */
  char *x;
  int j = 0;

  int bytes_written = 0;

  /*Tokenizes the command line, and immediately puts arguments on stack, as well as putting each argument on the stack into an array of stack pointers.*/
  for (x = strtok_r ((char *) file_name_and_args, " ", &save_ptr);
        x != NULL; x = strtok_r (NULL, " ", &save_ptr)) {
          int string_length = strlen(x) + 1;
          if_.esp -= string_length;
          bytes_written += string_length;
          strlcpy((char *) if_.esp, x, string_length);    
          stack_pointers[j] = (uint32_t) if_.esp;
          j++;
  }

  /* Round stack pointer down to multiple of 4 for word alignment*/
  uint8_t r;
  if ((r = (uint32_t) if_.esp % INT_SIZE)) {
      if_.esp -= r;
      bytes_written += r;
  }

  /* Add null terminator. */
  if_.esp -= INT_SIZE;
  *(uint32_t *) if_.esp = (uint32_t) NULL;
  bytes_written += INT_SIZE;

  /* For each argument decrement stack to right position and push pointer to address on the stack onto the stack.  */
  for (int i = j; i >= 0; i--) {
    if_.esp -= INT_SIZE;
    *(uint32_t *) if_.esp = stack_pointers[i];
    bytes_written += INT_SIZE;
  }

  /* Decrement stack to right position and push pointer to first argument pointer */
  if_.esp -= INT_SIZE;
  *(uint32_t *) if_.esp = (uint32_t) if_.esp + INT_SIZE;
  bytes_written += INT_SIZE;
  

  /* Decrement stack to right position and push number of arguments onto stack.  */
  if_.esp -= INT_SIZE;
  *(uint32_t *) if_.esp = (uint32_t) j;
  bytes_written += INT_SIZE;

  /* Decrement stack to right position and push fake address onto stack. */
  if_.esp -= INT_SIZE;
  *(uint32_t *) if_.esp = (uint32_t) NULL;
  bytes_written += INT_SIZE;

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  palloc_free_page(file_name_and_args);
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status. 
 * If it was terminated by the kernel (i.e. killed due to an exception), 
 * returns -1.  
 * If TID is invalid or if it was not a child of the calling process, or if 
 * process_wait() has already been successfully called for the given TID, 
 * returns -1 immediately, without waiting.
 * 
 * This function will be implemented in task 2.
 * For now, it does nothing. */
int
process_wait (tid_t child_tid)
{
    struct thread *child_thread = thread_with_tid(child_tid);

    if (child_thread == NULL || child_thread->parent != thread_current() ||
        child_thread->waited){
        return ERROR_RET;
    }
    if (child_thread->return_status != EXIT_SUCCESS || child_thread->exited) {
        return child_thread->return_status;
    }

    /* Waits for the child thread to sema up its wait_sema in process_exit to continue. */
    sema_down(&child_thread->wait_sema);

    /* Gets the child's return status whilst the child thread is blocked in process_exit. */
    int res = child_thread->return_status;

    /* Allows the child thread to continue exiting. */
    sema_up(&child_thread->exit_sema);
    child_thread->waited = true;
    file_allow_write(child_thread->executable);
    return res;
}

static void
sema_up_waiters(struct thread *cur) {
    while (!list_empty(&cur->wait_sema.waiters))
    /* Allows all threads blocked in process_wait to continue and get the current thread's return status. */
        sema_up(&cur->wait_sema);
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  sema_up_waiters(cur);

  cur->exited = true;

  if (cur->parent != NULL)
      /* Blocks until the parent thread gets the current thread's return status. */
      sema_down(&cur->exit_sema);

  /* If there is an executable, re-enable writes to the file and close it. */
  if (cur->executable != NULL) {
      lock_acquire(get_file_lock());
      file_allow_write(cur->executable);
      file_close(cur->executable);
      lock_release(get_file_lock());
  }

  /* Iterated through the mapped files list of thread owned mapped files and removes each from the global mmapped files 
     table, as well as freeing it.*/
  struct list_elem *k = list_begin(&cur->mapped_files);
  while (k != list_end(&cur->mapped_files)) {
      struct vm_file_mapping *file = list_entry(k, struct vm_file_mapping, list_elem);
      remove_from_mmap_table(file->mapping_id);
      k = list_next(k);
  }

  /* Iterates through the s_pages in the supplemental page table and frees the frame associated with the page, as the pages
     are no longer going to be used when the thread terminates. */
  lock_acquire(&cur->spt->page_table_lock);
  struct hash_iterator i;
  hash_first (&i, &cur->spt->spt_hash_table);
  while (hash_next (&i)) {
      struct s_page *sPage = hash_entry (hash_cur (&i), struct s_page, hash_elem);
      list_remove(&sPage->evict_elem);
      struct frame_element *f = find_frame(sPage->vaddr);
      remove_frame(&sPage->vaddr);

  }
  lock_release(&cur->spt->page_table_lock);
  spt_destroy(cur->spt);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);


    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();
  t->spt = spt_init();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */

  if (success) {
      /* Set current thread's executable to the file and disable writes. */
      thread_current()->executable = file;
      file_deny_write(file);
  } else {
      /* If the load is unsuccessful close the file. */
      file_close(file);
  }
  return success;
}

/* load() helpers. */

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);
  file_seek (file, ofs);

  off_t page_offset = ofs;
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Check if virtual page already allocated */
      struct thread *t = thread_current();
      struct spt *spt = t->spt;
      struct s_page *page = spt_get_element(spt, upage);
      /* If page is not in spt, insert a new page for it */
      if (page == NULL) {
        page = new_page (upage);
        spt_insert(spt, page);
      }
      /* Initialise the page structure's fields */
      page->offset = page_offset;
      page->file = file;
      page->read_bytes = page_read_bytes;
      page->zero_bytes = page_zero_bytes;
      /* Check if writable flag for the page should be updated */
      page->writeable |= writable;
      if (page_read_bytes > 0)
        page->type = FILE_SYS;
      else
        page->type = ALL_ZERO;

        /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      page_offset += PGSIZE;
      upage += PGSIZE;
    }
  file_seek(file, ofs);
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp)
{
  uint8_t *kpage;
  bool success = false;

  kpage = get_frame(PAL_USER | PAL_ZERO);
  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        remove_frame(kpage);
    }
  return true;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
