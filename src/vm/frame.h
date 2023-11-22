#ifndef PINTOS_25_FRAME_H
#define PINTOS_25_FRAME_H

#include <hash.h>
#include "threads/palloc.h"
#include "threads/thread.h"
#include "userprog/syscall.h"

typedef void* frame;

struct frame_element
{
    struct hash_elem hash_elem; /* Hash element for frame table. */
    struct list_elem list_elem; /* List element for the eviction list. */
    frame frame_addr;
    void* page;
    bool pinned;
};

struct hash* frame_table_init(void);

frame get_frame(enum palloc_flags flags);

void add_to_frame_table(struct hash_elem *hash_elem);

struct frame_element *find_frame(void *page);

bool remove_frame(void *page);

void free_frame(struct frame_element *f);

void evict(void);

void pin_page(void *page);

void pin_pages(void *page, unsigned size);

void unpin_pages(void *page, unsigned size);

void unpin_page(void *page);

#endif //PINTOS_25_FRAME_H
