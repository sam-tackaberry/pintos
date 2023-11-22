#ifndef PINTOS_25_SHARE_H
#define PINTOS_25_SHARE_H

#include <hash.h>
#include "threads/palloc.h"
#include "threads/thread.h"
#include "userprog/syscall.h"
#include "filesys/file.h"
#include "vm/frame.h"
#include "vm/page.h"
#include <stdlib.h>

struct fp_table_value {
    struct file *file;
    struct hash_elem hash_elem;
    struct hash *share_table;
};

struct lock *get_share_table_lock (void);
struct hash *get_share_table (void);

void share_table_init (void);
bool share_table_insert (struct s_page *s_page);
struct s_page* share_table_get_elem (void *file, void *vaddr);
bool share_table_remove_elem (void *file, void *vaddr);
void share_table_destroy (void);
struct hash * share_table_get_outer (void *file);

#endif //PINTOS_25_SHARE_H