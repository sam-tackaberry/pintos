#ifndef PINTOS_25_PAGE_H
#define PINTOS_25_PAGE_H

#include <hash.h>
#include "threads/palloc.h"
#include "threads/thread.h"
#include "userprog/syscall.h"
#include "filesys/file.h"
#include "vm/frame.h"
#include <stdlib.h>

typedef void* frame;

struct lock spt_lock;

/* Structure holding the supplemental page table, and it's associated lock */
struct spt {
    struct hash spt_hash_table;
    struct lock page_table_lock;
};

/* Types of pages we can load */
enum type {
    ALL_ZERO,
    SWAP_SLOT,
    FILE_SYS
};

/* Structure that goes into the supplemental page table */
struct s_page {
    void *vaddr;                 /* Virtual address of the page.*/
    enum type type;              /* Type of the page*/
    struct hash_elem hash_elem;  /* Hash element for the supplementary page table. */
    struct hash_elem share_elem; /* Hash element for the sharing table.*/
    struct hash_elem evict_elem; /* List element for the eviction list.*/
    bool valid;                  /* Value to check if the page can be accessed.*/
    struct file *file;           /* File that has been mapped to memory. */
    uint32_t offset;             /* Where in the file the pointer starts for this page. */
    uint32_t read_bytes;         /* Bytes in the page that need to be read. */
    uint32_t zero_bytes;         /* Bytes in the page that have been set to zero. */
    frame physical_page;         /* Address to frame that the page is mapped to.*/
    bool mmapped;                /* Has the file been memory mapped. */
    bool writeable;              /* Value used to che ck if the page is read only or not.*/
    void *pagedir;               /* Address to associated page in page directory*/
    size_t swap_index;           /* Keeps track of which slot the page has been put into in the swap table.*/
    bool dirty;                  /* Bool for if the page has been modified.*/
    bool accessed;               /* Bool for if the page has been accessed.*/

};

struct spt *spt_init (void);
struct s_page *spt_get_element (struct spt *spt, void *vaddr);
void spt_insert (struct spt *spt, struct s_page *page);
struct s_page *new_page (void *vaddr);
void free_page (struct hash_elem *hash_elem, void *aux UNUSED);
void spt_clear_page (struct spt *spt, struct s_page *page);
void spt_destroy (struct spt *spt);
bool page_load(struct s_page *page);
void page_unload(struct s_page *page);

#endif //PINTOS_25_PAGE_H