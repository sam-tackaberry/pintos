#include "vm/mmap.h"
#include <stdio.h>
#include <string.h>
#include "userprog/syscall.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "vm/page.h"


static bool hash_compare_fd (const struct hash_elem *a, const struct hash_elem *b, void *aux);
static unsigned mem_map_hash(const struct hash_elem *p, void *aux);

struct hash mem_map_files;
struct lock mem_map_files_lock;

/* Initialises memory mapping table and lock for the table. */
void
mem_map_files_init(void)
{
    lock_init(&mem_map_files_lock);
    hash_init(&mem_map_files, mem_map_hash, hash_compare_fd, NULL);
}

/* Create new mapping and add it to the table. */
struct vm_file_mapping*
add_to_map_table(int fd, void* start_address, void* end_address, int pages, mapid_t mapping_id)
{
    /* Malloc for a new mapping and exit if malloc fails. */
    struct vm_file_mapping *fm = malloc(sizeof (struct vm_file_mapping)); //MEMORY ALLOCATION
    if (fm == NULL)
        system_exit(-1);

    fm->fd = fd;
    fm->start_address = start_address;
    fm->end_address = end_address;
    fm->pages = pages;
    fm->mapping_id = mapping_id;

    lock_acquire(&mem_map_files_lock);
    hash_insert(&mem_map_files, &fm->hash_elem);
    lock_release(&mem_map_files_lock);
    return fm;
}

/* Given a unique mapping_id returns the corresponding mapping. */
struct vm_file_mapping*
find_mapping(mapid_t mapping_id)
{
    struct vm_file_mapping search_mapping;
    struct hash_elem *e;
    search_mapping.mapping_id = mapping_id;
    lock_acquire(&mem_map_files_lock);
    e = hash_find(&mem_map_files, &search_mapping.hash_elem);
    lock_release(&mem_map_files_lock);
    return e != NULL ? hash_entry(e, struct vm_file_mapping, hash_elem) : NULL;
}

/* Given a unique mapping_id finds the corresponding mapping and removes it from the table, and frees the mapping */
bool
remove_from_mmap_table(mapid_t mapping_id)
{
    struct vm_file_mapping *fm = find_mapping(mapping_id);
    if (fm == NULL)
        return false;

    lock_acquire(&mem_map_files_lock);
    struct hash_elem *e = hash_delete(&mem_map_files, &fm->hash_elem);
    lock_release(&mem_map_files_lock);

    free_mapping(&fm->hash_elem, NULL);
    return e != NULL;
}

/*Frees malloc of struct stored in hash table */
void
free_mapping(struct hash_elem *hash_elem, void *aux UNUSED)
{
    lock_acquire(&mem_map_files_lock);
    struct vm_file_mapping *fm = hash_entry(hash_elem, struct vm_file_mapping, hash_elem);
    free(fm);
    lock_release(&mem_map_files_lock);
}

static bool
hash_compare_fd (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    struct vm_file_mapping *fm1 = hash_entry(a, struct vm_file_mapping, hash_elem);
    struct vm_file_mapping *fm2 = hash_entry(b, struct vm_file_mapping, hash_elem);
    return fm1->mapping_id < fm2->mapping_id;
}

static unsigned
mem_map_hash(const struct hash_elem *p, void *aux UNUSED)
{
    const struct vm_file_mapping *fm = hash_entry(p,
            struct vm_file_mapping, hash_elem);
    return hash_int(fm->mapping_id);
}

/*Destroys the mmap table and frees malloc-ed structs inside */
void
mmap_table_destroy (void) {
    lock_acquire(&mem_map_files_lock);
    hash_destroy(&mem_map_files, free_mapping);
    lock_release(&mem_map_files_lock);
}