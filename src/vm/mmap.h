#ifndef PINTOS_25_MMAP_H
#define PINTOS_25_MMAP_H

#include "userprog/syscall.h"
#include <hash.h>
#include "threads/synch.h"

typedef int mapid_t;

struct vm_file_mapping{
    int fd;                     /* File descriptor of file mapped into memory. */
    void* start_address;        /* Starting address in memory of where the file is mapped. */
    void* end_address;          /* End address in memory of where the file is mapped. */
    int pages;
    /* Number of pages the mapping spans in memory. */
    struct hash_elem hash_elem; /* Hash element for the memory mapping table. */
    struct list_elem list_elem; /* List element for the thread's list of memory mapped files. */
    mapid_t mapping_id;         /* Unique mapping id for the mapping. */
};

void mem_map_files_init(void);
struct vm_file_mapping* add_to_map_table(int fd, void* start_address, void* end_address, int pages, mapid_t mapping_id);
bool remove_from_mmap_table(mapid_t mapping_id);
struct vm_file_mapping* find_mapping(mapid_t mapping_id);
void free_mapping(struct hash_elem *hash_elem, void *aux);
void mmap_table_destroy (void);

#endif //PINTOS_25_MMAP_H
