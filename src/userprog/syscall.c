#include <stdio.h>
#include <string.h>
#include "threads/malloc.h"
#include "userprog/syscall.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "lib/syscall-nr.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "devices/input.h"
#include "filesys/inode.h"
#include "vm/frame.h"

#ifdef VM
#include "vm/mmap.h"
#include "vm/page.h"
#include "userprog/exception.h"

#endif

typedef void (*func_handler) (void);
static func_handler func_handler_map[NUMBER_OF_SYSTEM_CALLS];

static void halt (void);
static pid_t exec (const char *cmd_line);
static int wait (pid_t pid);
static bool create (const char *file, unsigned initial_size);
static bool remove (const char *file);
static int open (const char *file);
static int filesize (int fd);
static int read (int fd, void *buffer, unsigned size);
static int write(int fd, const void *buffer, unsigned size);
static void seek(int fd, unsigned position);
static unsigned tell(int fd);
static void close(int fd);
static mapid_t mmap (int fd, void *addr);
static void munmap (mapid_t mapping);
static mapid_t allocate_mapping_id(void);

_Atomic mapid_t map_id = 0;

struct file_container {
    struct file *file;           /* Pointer to file */
    int file_id;                 /* File id */
    struct list_elem file_elem;  /* List elem for the list of open files. */
};

/* Lock to ensure synchronised access to the file system. */
struct lock file_lock;
struct lock mem_lock;

static struct file_container *fd_to_file(int fd);

static bool is_valid_pointer (const void *pointer);

int32_t get_user (const uint8_t *uaddr);

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
    func_handler_map[SYS_HALT] =  (func_handler) halt;
    func_handler_map[SYS_EXIT] =  (func_handler) system_exit;
    func_handler_map[SYS_EXEC] =  (func_handler) exec;
    func_handler_map[SYS_WAIT] = (func_handler) wait;
    func_handler_map[SYS_CREATE] = (func_handler) create;
    func_handler_map[SYS_REMOVE] = (func_handler) remove;
    func_handler_map[SYS_OPEN] =  (func_handler) open;
    func_handler_map[SYS_FILESIZE] = (func_handler) filesize;
    func_handler_map[SYS_READ] =  (func_handler) read;
    func_handler_map[SYS_WRITE] = (func_handler) write;
    func_handler_map[SYS_SEEK] =  (func_handler) seek;
    func_handler_map[SYS_TELL] = (func_handler) tell;
    func_handler_map[SYS_CLOSE] = (func_handler) close;
    func_handler_map[SYS_MMAP] = (func_handler) mmap;
    func_handler_map[SYS_MUNMAP] = (func_handler) munmap;
    lock_init(&file_lock);
    lock_init(&mem_lock);
}


static void
syscall_handler (struct intr_frame *f UNUSED) 
{
    uint32_t *stack_pointer = f->esp;
    int res = 0;

    /* Checks if all parameters are valid. */
    if (!is_valid_pointer(stack_pointer) || !is_valid_pointer(stack_pointer + 1) || !is_valid_pointer(stack_pointer + 2) || !is_valid_pointer(stack_pointer + 3))
        system_exit(ERROR_RET);


    /* Lookup enum in map and get address of function */
    func_handler func = func_handler_map[*stack_pointer];
    uint32_t (*f1) (uint32_t, uint32_t, uint32_t) = (uint32_t (*)(uint32_t, uint32_t, uint32_t)) func;
    res = f1 (*(stack_pointer + 1), *(stack_pointer + 2), *(stack_pointer + 3));

    /* Store result of system call function in the eax register. */
    f->eax = res;
}

void
halt (void)
{
    shutdown_power_off();
}

void
system_exit (int status)
{
    struct thread *t = thread_current();

    /* Release file_lock if the process is currently accessing the file system. */
    if (file_lock.holder != t && file_lock.holder != NULL)
        file_lock.holder = t;
    if (file_lock.holder == t)
        lock_release(&file_lock);


    /* Close all the thread's open files. */
    struct list_elem *e;
    while (!list_empty(&t->files_open)) {
        e = list_begin(&t->files_open);
        struct file_container *f = list_entry(e, struct file_container, file_elem);
        close(f->file_id);
    }

    /* Unmap all the current thread's file mappings */
    struct list_elem *f;
    while (!list_empty(&t->mapped_files)) {
        f = list_begin(&t->mapped_files);
        struct vm_file_mapping *fm = list_entry(f, struct vm_file_mapping, list_elem);
        munmap(fm->mapping_id);
    }

    /* Remove thread elem from parent's list of children processes */
    if (t->parent != NULL && (strcmp(t->parent->name, "main") != 0))
        list_remove(&t->childelem);

    /* Sets the return status and exited field of the current thread. */
    t->return_status = status;
    t->exited = true;
    printf("%s: exit(%d)\n", t->name, t->return_status);
    thread_exit();
    mmap_table_destroy();
}

pid_t
exec (const char *cmd_line)
{
    if (!is_valid_pointer(cmd_line))
        system_exit(ERROR_RET);

    lock_acquire(&file_lock);
    int res = process_execute(cmd_line);
    lock_release(&file_lock);
    return res;
}

int
wait (pid_t pid)
{
    return process_wait(pid);
}

bool
create (const char *file, unsigned initial_size)
{
    if (!is_valid_pointer(file))
        system_exit(ERROR_RET);

    lock_acquire(&file_lock);
    bool status = filesys_create(file, initial_size);
    lock_release(&file_lock);
    return status;
}

bool
remove (const char *file)
{
    if (!is_valid_pointer(file))
        system_exit(ERROR_RET);

    lock_acquire(&file_lock);
    bool status = filesys_remove(file);
    lock_release(&file_lock);
    return status;
}

int
open (const char *file)
{
    if (!is_valid_pointer(file))
        system_exit(ERROR_RET);

    lock_acquire(&file_lock);
    struct file *f = filesys_open(file);
    lock_release(&file_lock);

    if (f == NULL)
        return ERROR_RET;

    /* Malloc a new file container to store the opened file, fid and list elem. */
    struct file_container *container = (struct file_container *) malloc(sizeof(struct file_container));

    /* Close and free container if malloc fails. */
    if (container == NULL) {
        lock_acquire(&file_lock);
        file_close(f);
        lock_release(&file_lock);
        return ERROR_RET;
    }

    lock_acquire(&file_lock);
    struct thread *t = thread_current();
    container->file = f;
    if (list_empty(&t->files_open)) {
        /* First open file has a fid of 2. */
        container->file_id = INITIAL_FID;
    } else {
        /* Fid set to one more than the most recent open file. */
        container->file_id = list_entry(list_back(&t->files_open), struct file_container, file_elem)->file_id + 1;
    }

    /* File pushed to the back of the current thread's open files. */
    list_push_back(&t->files_open, &container->file_elem);

    lock_release(&file_lock);
    return container->file_id;
}



int
filesize (int fd)
{
    lock_acquire(&file_lock);
    struct file_container *container = fd_to_file(fd);
    lock_release(&file_lock);
    if (container == NULL)
        return ERROR_RET;
    
    lock_acquire(&file_lock);
    int size = file_length(container->file);
    lock_release(&file_lock);
    return size;
}
static bool
put_user (uint8_t *udst, uint8_t byte)
{
    int error_code;
    asm ("movl $1f, %0; movb %b2, %1; 1:"
            : "=&a" (error_code), "=m" (*udst) : "q" (byte));
    return error_code != -1;
}


int
read (int fd, void *buffer, unsigned size)
{
    if (get_user((const uint8_t*) buffer) == -1 || get_user((const uint8_t*) buffer + size - 1) == -1)
       system_exit(ERROR_RET);

    int bytes_read = 0;
    if (file_lock.holder != thread_current())
        lock_acquire(&file_lock);

    if (fd == STDOUT_FILENO) {
        /* If the fd is set for standard output, exit. */
        lock_release(&file_lock);
        system_exit(ERROR_RET);
    } else if (fd == STDIN_FILENO) {
        /* Read from the keyboard. */
        uint8_t* buffer_input = (uint8_t *) buffer;
        for (unsigned i = 0; i < size; i++) {
            uint8_t key = input_getc();
            buffer_input[i] = key;
        }
        lock_release(&file_lock);
    } else {
        /* Reads from the open file to the buffer, returns -1 if file cannot be found. */
        struct file_container *file_to_read = fd_to_file(fd);
        if (file_to_read == NULL) {
            lock_release(&file_lock);
            return ERROR_RET;
        }

        unsigned char *temp_buffer = malloc(size); // need to free
        pin_pages(temp_buffer, size);
        int actual_size = file_read(file_to_read->file, temp_buffer, size);
        lock_release(&file_lock);
        pin_pages(buffer, actual_size);
        while (bytes_read < actual_size) {
            if (put_user(buffer + bytes_read, temp_buffer[bytes_read]))
                bytes_read++;
            else {
                unpin_pages(temp_buffer, size);
                free(temp_buffer);
                system_exit(ERROR_RET);
            }
        }
        unpin_pages(temp_buffer, size);
        unpin_pages(buffer, actual_size);
        free(temp_buffer);
    }


    return bytes_read;
}


int
write(int fd, const void *buffer, unsigned size)
{
    if (get_user((const uint8_t*) buffer) == -1 || get_user((const uint8_t*) buffer + size - 1) == -1)
       system_exit(ERROR_RET);

    int bytes_written = 0;
    lock_acquire(&file_lock);
    if (fd == STDOUT_FILENO) {
        /* Write 500 bytes at a time to the console. */
        while(size > 0) {
            int line_size = (size > MAX_BUFFER_WRITE_SIZE) ? MAX_BUFFER_WRITE_SIZE : size;
            putbuf(buffer, line_size);
            size -= line_size;
            bytes_written += line_size;
        }
    } else if (fd == STDIN_FILENO) {
        /* If fd is set for standard input, exit. */
        lock_release(&file_lock);
        system_exit(ERROR_RET);
    } else {
        /* Write from the buffer to the file fd, exits if file cannot be found. */
        struct file_container *file_to_write = fd_to_file(fd);
        if (file_to_write == NULL) {
            lock_release(&file_lock);
            system_exit(ERROR_RET);
        }
        bytes_written = file_write(file_to_write->file, buffer, size);
    }
    lock_release(&file_lock);
    return bytes_written;
}

void
seek(int fd, unsigned position)
{
    lock_acquire(&file_lock);
    struct file_container *container = fd_to_file(fd);
    lock_release(&file_lock);

    /* If the file with that fid cannot be found, system_exit. */
    if (container == NULL)
        system_exit(ERROR_RET);

    lock_acquire(&file_lock);
    file_seek(container->file, position);
    lock_release(&file_lock);
}


unsigned
tell(int fd)
{
    lock_acquire(&file_lock);
    struct file_container *container = fd_to_file(fd);
    lock_release(&file_lock);
    /* If the file with that fid cannot be found, system_exit. */
    if (container == NULL)
        system_exit(ERROR_RET);

    lock_acquire(&file_lock);
    int32_t position = file_tell(container->file);
    lock_release(&file_lock);
    return position;
}

void
close(int fd)
{
    lock_acquire(&file_lock);
    struct file_container *container = fd_to_file(fd);
    lock_release(&file_lock);
    /* If the file with that fid cannot be found, system_exit. */
    if (container == NULL) 
        system_exit(ERROR_RET);
        
    lock_acquire(&file_lock);

    /* Remove file from the list of open files and free the file container structure once the file is closed. */
    list_remove(&container->file_elem);
    file_close(container->file);
    free(container);
    lock_release(&file_lock);   
}

mapid_t
mmap (int fd, void *addr)
{
    /* Return -1 if any of the error cases are met. */
    if (fd == STDOUT_FILENO || fd == STDIN_FILENO || addr == 0 || pg_ofs(addr) != 0)
        return ERROR_RET;
    lock_acquire(&file_lock);
    struct file_container *fc = fd_to_file(fd);
    lock_release(&file_lock);
    if (fc == NULL)
        return ERROR_RET;

    lock_acquire(&file_lock);
    struct file *f = file_reopen(fc->file);
    lock_release(&file_lock);
    if (f == NULL)
        return ERROR_RET;

    void *curr_addr = addr;
    int size = filesize(fd);
    if (size == 0) {
        /* Add an invalid page to the supplementary page table and return -1. */
        struct s_page *p = new_page(curr_addr);
        p->valid = false;
        spt_insert(thread_current()->spt, p);
        return ERROR_RET;
    }

    uint32_t offset = 0;
    int pages = 0;
    while (size > 0) {
        /* read_bytes set to the smallest between the remaining bytes in the file to be processed and page size. */
        size_t read_bytes = size < PGSIZE ? size : PGSIZE;
        /* If read_bytes isn't page size, zero_bytes set to the remaining bytes of the page. */
        size_t zero_bytes = PGSIZE - read_bytes;
        struct s_page *p = spt_get_element(thread_current()->spt, curr_addr);

        /* Return if pages overlap any existing pages. */
        if (p != NULL || ((unsigned) curr_addr >= (unsigned) (PHYS_BASE - PGSIZE)))
            return ERROR_RET;

        /* Create a new page at the current address and insert it to the supplementary page table. */
        p = new_page(curr_addr);
        spt_insert(thread_current()->spt, p);

        p->mmapped = true;
        p->writeable = true;
        p->type = FILE_SYS;
        p->file = f;
        //p->owner = thread_current();
        p->read_bytes = read_bytes;
        p->zero_bytes = zero_bytes;
        p->offset = offset;
        pages++;

        size -= read_bytes;
        curr_addr += PGSIZE;
        offset += PGSIZE;
    }
    /* Allocates a unique mapping id and adds the mapping to the memory mapped table
     * and the current thread's list of memory mapped files. */
    int map_id = allocate_mapping_id();
    struct vm_file_mapping *fm = add_to_map_table(fd, addr, curr_addr, pages, map_id);
    lock_acquire(&mem_lock);
    list_push_back(&thread_current()->mapped_files, &fm->list_elem);
    lock_release(&mem_lock);
    return map_id;
}

void
munmap (mapid_t mapping)
{
    /* Return if the mapping doesn't exist in the mapping table. */
    struct vm_file_mapping *fm = find_mapping(mapping);
    if (fm == NULL) {
        system_exit(ERROR_RET);
    }
    /* Remove mapping from the current thread's list of memory mapped files. */
    lock_acquire(&mem_lock);
    list_remove(&fm->list_elem);
    for (int i = 0; i < fm->pages; i++) {
        /* Gets the every mapped page from memory and if they aren't null unloads the pages. */
        struct s_page *p = spt_get_element(thread_current()->spt, fm->start_address + (i * PGSIZE));

        if (p != NULL) {
            p->mmapped = false;
            p->valid = false;
            page_unload(p);
        }
    }
    lock_release(&mem_lock);
    remove_from_mmap_table(fm->mapping_id);
}

/* Checks that the pointer isn't null, is a valid user virtual address and has a corresponding kernel virtual address. */
static bool
is_valid_pointer (const void *pointer) {
    if (pointer != NULL && is_user_vaddr(pointer)) {
        return pagedir_get_page(thread_current()->pagedir, pointer) != NULL;
    }
    return false;
}

/* Returns the file container from the current thread's open files with the corresponding fid. */
static struct file_container*
fd_to_file(int fd)
{

    struct thread *t = thread_current();
    struct list_elem *e = list_begin(&t->files_open);
    while (e != list_end(&t->files_open)) {
        struct file_container *f = list_entry(e, struct file_container, file_elem);
        if (fd == f->file_id)
            return f;
        e = list_next(e);
    }
    return NULL;
}

/* Returns a unique mapping id. */
static
mapid_t allocate_mapping_id(void) {
    return map_id++;
}

/* Used by functions from other files to lock the file lock when accessing file system */
struct lock*
get_file_lock(void) {
    return &file_lock;
}

/* check that a user pointer uaddr points below PHYS_BASE */
int32_t
get_user (const uint8_t *uaddr) {

    if (! ((void*)uaddr < PHYS_BASE)) {
        return ERROR_RET;
    }

    int result;
    asm ("movl $1f, %0; movzbl %1, %0; 1:"
            : "=&a" (result) : "m" (*uaddr));
    return result;
}
