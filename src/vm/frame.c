#include "vm/frame.h"
#include <stdio.h>
#include <stdbool.h>
#include "userprog/syscall.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "vm/page.h"
#include "vm/share.h"
#include "userprog/pagedir.h"

#define PGSIZE 4096

struct hash frame_table;
struct lock frame_table_lock;

struct list eviction_list;
struct lock eviction_list_lock;

static bool hash_compare_key(const struct hash_elem *a, const struct hash_elem *b,
                      void *aux UNUSED);

static unsigned frame_element_hash(const struct hash_elem *p, void *aux UNUSED);


/* Initialises frame table and lock for the table. */
struct hash*
frame_table_init(void)
{
    hash_init(&frame_table, frame_element_hash, hash_compare_key,  NULL);
    lock_init(&frame_table_lock);
    lock_init(&eviction_list_lock);
    list_init(&eviction_list);
    return &frame_table;
}

/* Compares frame addresses (the keys) */
static bool
hash_compare_key(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    struct frame_element *kvpa = hash_entry(a, struct frame_element, hash_elem);
    struct frame_element *kvpb = hash_entry(b, struct frame_element, hash_elem);
    return (kvpa->frame_addr < kvpb->frame_addr);
}

/* Hashing on the frame address with hash_bytes from manual */
static unsigned
frame_element_hash(const struct hash_elem *p, void *aux UNUSED)
{
    const struct frame_element *frame_element = hash_entry(p,
        struct frame_element, hash_elem);
    return hash_bytes(&frame_element->frame_addr, sizeof(frame_element->frame_addr));
}

/* Palloc for a new page and create a frame to add to the frame table. */
frame
get_frame(enum palloc_flags flags)
 {
     frame f_addr = palloc_get_page(flags);
     if (f_addr == NULL) {
         evict();
         return get_frame(flags);
     }

     /* Malloc a new frame_element and exit if malloc fails. */
     struct frame_element *f = malloc (sizeof (struct frame_element)); //Memory Allocation

     if (f == NULL)
         system_exit(-1);

     f->frame_addr = f_addr;
     f->pinned = true;

     add_to_frame_table(&f->hash_elem);
     lock_acquire(&eviction_list_lock);
     list_push_back(&eviction_list, &f->list_elem);
     lock_release(&eviction_list_lock);
     return f_addr;
}

/* Add frame to frame table. */
void
add_to_frame_table(struct hash_elem *hash_elem)
{
    lock_acquire(&frame_table_lock);
    hash_insert(&frame_table, hash_elem);
    lock_release(&frame_table_lock);
}

/* Return the corresponding frame from the frame table given the page. */
struct frame_element *
find_frame(void *page)
{
    struct frame_element f;
    struct hash_elem *e;
    f.frame_addr = page;
    lock_acquire(&frame_table_lock);
    e = hash_find(&frame_table, &f.hash_elem);
    lock_release(&frame_table_lock);
    return e != NULL ? hash_entry(e, struct frame_element, hash_elem) : NULL;
}

/* Removes the frame from the hash table and frees the data structure. */
bool
remove_frame(void *page)
{
    struct frame_element *f = find_frame(page);
    if (f == NULL) {
        return false;
    }
    lock_acquire(&frame_table_lock);
    struct hash_elem *e = hash_delete(&frame_table, &f->hash_elem);
    lock_release(&frame_table_lock);
    bool res = e != NULL;
    free_frame(f);
    return res;
}

/* Frees malloced frame_element struct*/
void
free_frame(struct frame_element *f)
{
    palloc_free_page(f->page);
    free(f);
}

void
evict(void)
{
    lock_acquire(&frame_table_lock);
    struct frame_element *f = NULL;
    lock_acquire(&eviction_list_lock);
    struct list_elem *e = list_begin(&eviction_list);
    struct s_page *page;

    /* Iterate through our eviction list until a victim frame is found. */
    while (f == NULL) {
        struct frame_element *temp = list_entry(e, struct frame_element, list_elem);
        if (!pagedir_is_accessed(thread_current()->pagedir, temp->page) && !temp->pinned) {
            page = spt_get_element(thread_current()->spt, temp->page);
            
            lock_acquire(get_share_table_lock());

            /* Go through the share table and check if we have another s_page that references the victim frame. */
            struct hash_iterator i;
            hash_first (&i, get_share_table());
            while (hash_next (&i)) {

                struct hash *h = hash_entry(hash_cur (&i), struct fp_table_value, hash_elem)->share_table;
                struct s_page dummy_paddr_table_value;
                dummy_paddr_table_value.vaddr = temp->page;
                struct hash_elem *elem = hash_find(h, &dummy_paddr_table_value.share_elem);
                /* If we have an entry in the share table, check all the accessed bits for 
                the s_pages that rely on the victim frame. If any are set, we need to set 
                them to false and break out of the loop as we won't be able to evict this frame this time.*/
                if (elem != NULL) {
                    struct hash_iterator i2;
                    hash_first (&i2, h);
                    while (hash_next (&i2)) {
                        struct s_page *p = hash_entry(hash_cur (&i), struct s_page, share_elem);
                        if (pagedir_is_accessed(p->pagedir, p->vaddr)) {
                            pagedir_set_accessed(p->pagedir, p->vaddr, false);
                            break;
                        } else
                            continue;
                    }
                    break;
                }
               
            }
            /* If we don't have an entry in the share table, we just need to check if the page
             we currently have is NULL. If it is NULL we should keep looking, otherwise we will 
             break out of the loop and set the victim frame to the current temp frame. */
            lock_release(get_share_table_lock());
            if (page != NULL) {
                f = temp;
                break;
            }
        } else {
            pagedir_set_accessed(thread_current()->pagedir, temp->page, 0);
        }

        /* If we haven't found a victim, keep looking. If we're at the end of the list,
         go around again in case we have a victim now thanks to changing the accessed bit. */
        if (list_next(e) == list_end(&eviction_list))
            e = list_begin(&eviction_list);
        else
            e = list_next(e);
    }
    /* If the page has a file, it might be shared. */
    lock_release(&eviction_list_lock);
    if (page->file != NULL) {
        struct hash *shared_spages = share_table_get_outer(page->file);
        if (shared_spages != NULL) {
            lock_acquire(get_share_table_lock());
            struct hash_iterator i;
            hash_first (&i, shared_spages);
            while (hash_next (&i)) {
                struct s_page *p = hash_entry (hash_cur (&i), struct s_page, evict_elem);
                p->type = SWAP_SLOT;
                if (pagedir_is_dirty(p->pagedir, p->vaddr))
                    p->dirty = true;
                pagedir_clear_page(thread_current()->pagedir, p->vaddr);
                p->physical_page = NULL;
            }
            lock_release(get_share_table_lock());
        }
    }
    page->type = SWAP_SLOT;
    
    lock_release(&frame_table_lock);
    if (page->physical_page == NULL)
        page->physical_page = f->frame_addr;
    page_unload(page);
    lock_acquire(&frame_table_lock);
    lock_acquire(&eviction_list_lock);
    list_remove(&f->list_elem);
    lock_release(&eviction_list_lock);
    hash_delete(&frame_table, &f->hash_elem);
    free(f);
    pagedir_clear_page(page->pagedir, page->vaddr);
    page->physical_page = NULL;
    lock_release(&frame_table_lock);
}


void
pin_pages(void *page, unsigned size) {
    for (unsigned i = 0; i < size; i++) {
        struct frame_element *f = find_frame(page + size);
        if (f != NULL)
            f->pinned = true;
    }
}

void
unpin_pages(void *page, unsigned size) {
    for (unsigned i = 0; i < size; i++) {
        struct frame_element *f = find_frame(page + size);
        if (f != NULL)
            f->pinned = false;
    }
}

void
pin_page(void *page) {
    struct frame_element *f = find_frame(page);
    f->pinned = true;
}

void
unpin_page(void *page) {
    struct frame_element *f = find_frame(page);
    f->pinned = false;
}
