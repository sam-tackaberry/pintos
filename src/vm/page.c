#include "vm/page.h"
#include "vm/share.h"
#include "devices/swap.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include <string.h>
#include "threads/thread.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"

#include <stdio.h>

static unsigned spt_hash_func (const struct hash_elem *element, void *aux UNUSED);
static bool spt_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
static bool load_file_to_page (struct s_page *page);
static void load_zero_to_page(void *page);

struct lock swap_lock;

/* Initialises the supplementary page table and the lock for the table. */
struct spt*
spt_init (void)
{
    struct spt *spt = malloc(sizeof (struct spt));
    lock_init(&spt->page_table_lock);
    lock_init(&swap_lock);
    hash_init(&spt->spt_hash_table, spt_hash_func, spt_less_func, NULL);
    return spt;
}

/* Given a virtual address, returns the page in the supplementary page table with that vaddr. */
struct s_page*
spt_get_element (struct spt *spt, void *vaddr)
{
    struct s_page p;
    struct hash_elem *e;
    p.vaddr = vaddr;

    lock_acquire(&spt->page_table_lock);
    e = hash_find(&spt->spt_hash_table, &p.hash_elem);
    lock_release(&spt->page_table_lock);

    return e != NULL ? hash_entry(e, struct s_page, hash_elem) : NULL;
}

/* Adds given page to the supplementary page table. */
void
spt_insert (struct spt *spt, struct s_page *page)
{
    lock_acquire(&spt->page_table_lock);
    hash_insert(&spt->spt_hash_table, &page->hash_elem);
    lock_release(&spt->page_table_lock);
}

/* Creates a new s_page. */
struct s_page*
new_page (void *vaddr)
{
    /* Malloc a new s_page and exit if malloc fails. */
    struct s_page *page = malloc(sizeof (struct s_page));
    if (page == NULL)
        return NULL;

    page->vaddr = vaddr;
    page->zero_bytes = 0;
    page->read_bytes = PGSIZE;
    page->writeable = false;
    page->valid = true;
    page->type = ALL_ZERO;
    page->mmapped = false;
    page->pagedir = thread_current()->pagedir;
    page->dirty = false;
    page->accessed = false;

    return page;
}

/* Frees malloc on struct of page stored in table*/
void
free_page (struct hash_elem *hash_elem, void *aux UNUSED)
{
    struct s_page *page = hash_entry(hash_elem, struct s_page, hash_elem);
    free(page);
}

/* Removes the page from the supplementary page table. */
void
spt_clear_page (struct spt *spt, struct s_page *page)
{
    lock_acquire(&spt->page_table_lock);
    hash_delete(&spt->spt_hash_table, &page->hash_elem);
    share_table_remove_elem(page->file, page->vaddr);
    free(page);
    lock_release(&spt->page_table_lock);
}

/* Destroys supplementary page table and frees all pages. */
void
spt_destroy (struct spt *spt)
{
    lock_acquire(&spt->page_table_lock);
    hash_destroy(&spt->spt_hash_table, &free_page);
    lock_release(&spt->page_table_lock);
}

static unsigned
spt_hash_func (const struct hash_elem *element, void *aux UNUSED)
{
    return hash_ptr(hash_entry(element, struct s_page, hash_elem)->vaddr);
}

static bool
spt_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    const unsigned a_ = (unsigned) hash_entry(a, struct s_page, hash_elem)->vaddr;
    const unsigned b_ = (unsigned) hash_entry(b, struct s_page, hash_elem)->vaddr;
    return a_ < b_;
}


static bool
load_file_to_page (struct s_page *page)
{
    /* Set current page position to the offset. */

    lock_acquire(get_file_lock());
    file_seek (page->file, page->offset);

    /* Read page_read_bytes bytes from the file into the physical page. */
    pin_pages(page->physical_page, 1);
    if (file_read (page->file, page->physical_page, page->read_bytes) != (int) page->read_bytes) {
        /* If the total bytes read isn't the same as expected return false. */
        unpin_pages(page, 1);
        lock_release(get_file_lock());
        return false;
    }
    
    lock_release(get_file_lock());
    /* Set the remaining space in the page to 0. */
    memset (page->physical_page + page->read_bytes, 0, page->zero_bytes);
    unpin_pages(page->physical_page, 1);

    return true;
}

/* Set the whole page to 0. */
static void
load_zero_to_page(frame page)
{
    memset(page, 0, PGSIZE);
}


static bool
load_swap(struct s_page *page)
{
    lock_acquire(&swap_lock);
    swap_in(page->physical_page, page->swap_index);
    pagedir_set_dirty(page->pagedir, page->vaddr, page->dirty);
    lock_release(&swap_lock);
    return true;
}

/* Loads a given page into memory. */
bool
page_load(struct s_page *page)
{
    struct spt *spt = thread_current()->spt;
    lock_acquire(&spt->page_table_lock);
    bool success = false;
    if (page->physical_page == NULL) {
        page->physical_page = get_frame(PAL_USER);
        struct frame_element *f = find_frame(page->physical_page);
        f->page = page->vaddr;
    }

    switch (page->type) {
        case ALL_ZERO:
            load_zero_to_page(page->physical_page);
            success = true;
            break;
        case SWAP_SLOT:
            success = load_swap(page);
            break;
        case FILE_SYS:
            success = load_file_to_page(page);
            break;
    }

    if (!success) {
        lock_release(&spt->page_table_lock);
        unpin_page(page->physical_page);
        return false;
    }

    lock_release(&spt->page_table_lock);
    pagedir_clear_page(page->pagedir, page->vaddr);

    pagedir_set_page(page->pagedir,
        page->vaddr, page->physical_page, page->writeable);

    if (page->type != SWAP_SLOT)
        pagedir_set_dirty(page->pagedir, page->vaddr, false);
    pagedir_set_accessed(page->pagedir, page->vaddr, true);

    unpin_page(page->physical_page);

    return success;
}

/* Writes the file from the page back to memory and frees the page. */
void
page_unload(struct s_page *page)
{
    if (page->type == FILE_SYS && pagedir_is_dirty(page->pagedir, page->vaddr)) {
        lock_acquire(get_file_lock());
        /* Sets the pointer in the page to the offset. */
        file_seek(page->file, page->offset);
        file_write(page->file, page->vaddr, page->read_bytes);
        lock_release(get_file_lock());
        palloc_free_page(page->physical_page);
        pagedir_clear_page(page->pagedir, page->vaddr);
        page->physical_page = NULL;
        page->valid = false;
        /* If the page has been modified, write from the virtual address into the file .*/
    } else if (page->type == SWAP_SLOT) {
        lock_acquire(&swap_lock);
        page->swap_index = swap_out(page->physical_page);
        palloc_free_page(page->physical_page);
        lock_release(&swap_lock);
    }

}
