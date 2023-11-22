#include "vm/share.h"
#include "vm/page.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"

#include <stdio.h>
#include <string.h>

static unsigned share_table_fp_hash_func (const struct hash_elem *element, void *aux UNUSED);
static bool share_table_fp_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
static unsigned spage_hash_func (const struct hash_elem *element, void *aux UNUSED);
static bool spage_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
static void inner_table_destroy (struct hash_elem *hash_elem, void *aux UNUSED);

struct hash share_table_fp;
struct lock fp_table_lock;

/* Initialises share table and lock for it. */
void
share_table_init (void)
{
    lock_init(&fp_table_lock);
    hash_init(&share_table_fp, share_table_fp_hash_func, share_table_fp_less_func,  NULL);
}

struct hash *
get_share_table (void) {
    return &share_table_fp;
}

struct lock *
get_share_table_lock (void) {
    return &fp_table_lock;
}

bool
share_table_insert (struct s_page *s_page)
{

    /* Initialise the value for the first hash map */
    struct fp_table_value fp_table_dummy;
    fp_table_dummy.file = s_page->file;

    lock_acquire(&fp_table_lock);

    /* If the file pointer is not in the first hash map, add the file pointer with an 
    empty inner hash map, and add the vaddr to the inner hash map */
    struct hash_elem *fpLookup = hash_find(&share_table_fp, &fp_table_dummy.hash_elem);
    if (fpLookup == NULL) {
        /* Create a new table container and share table and exit if malloc fails. */
        struct fp_table_value *new_table = malloc(sizeof (struct fp_table_value)); /* MEMORY ALLOCATION */
        if (new_table == NULL)
            system_exit(ERROR_RET);
        new_table->share_table = malloc(sizeof (struct hash)); /* MEMORY ALLOCATION */
        if (new_table->share_table == NULL)
            system_exit(ERROR_RET);
        /* Initialises the new table. */
        hash_init(new_table->share_table, spage_hash_func, spage_less_func, NULL);
        /* Insert new table into outer table. */
        hash_insert(&share_table_fp, &new_table->hash_elem);
        /* Inserts the s_page into the new inner table. */
        hash_insert(new_table->share_table, &s_page->share_elem);
    } else {
        /* Finds the existing inner table and adds the s_page to it. */
        struct hash *inner_table = hash_entry(fpLookup, struct fp_table_value, hash_elem)->share_table;
        hash_insert(inner_table, &s_page->share_elem);
    }

    lock_release(&fp_table_lock);
    return true;
}

/* Searches file pointer and vaddr key in share table to get a s_page pointer, or NULL if it does not exist in the
   share table. */
struct s_page*
share_table_get_elem (void *file, void *vaddr)
{
    lock_acquire(&fp_table_lock);

    /* Creates dummy elements. */
    struct fp_table_value dummy_fp_table_value;
    dummy_fp_table_value.file = file;

    /* Gets inner hashmap from outer hashmap. */
    struct hash_elem *elem = hash_find(&share_table_fp, &dummy_fp_table_value.hash_elem);
    /* If the inner hashmap does not exist, return. */
    if (elem == NULL) {
        lock_release(&fp_table_lock);
        return NULL;
    }

    struct hash *share_table = hash_entry(elem, struct fp_table_value, hash_elem)->share_table;
    struct s_page dummy_paddr_table_value;
    dummy_paddr_table_value.vaddr = vaddr;

    /*Get s_page from inner hashmap based on the page address key*/
    struct hash_elem *elem2 = hash_find(share_table, &dummy_paddr_table_value.share_elem);
    lock_release(&fp_table_lock);
    return elem2 != NULL ? hash_entry(elem2, struct s_page, share_elem) : NULL;
}

struct hash *
share_table_get_outer (void *file)
{
    lock_acquire(&fp_table_lock);

    /* Creates dummy elements. */
    struct fp_table_value dummy_fp_table_value;
    dummy_fp_table_value.file = file;

    /* Gets outer hashmap. */
    struct hash_elem *elem = hash_find(&share_table_fp, &dummy_fp_table_value.hash_elem);
    /* If the inner hashmap does not exist, return. */
    if (elem == NULL) {
        lock_release(&fp_table_lock);
        return NULL;
    }

    struct hash *share_table = hash_entry(elem, struct fp_table_value, hash_elem)->share_table;
    lock_release(&fp_table_lock);
    return share_table;
}

bool
share_table_remove_elem (void *file, void *vaddr) {
    /* Check that the element being returned exists in the hashmap. */
    if (share_table_get_elem(file, vaddr) == NULL)
        return false;

    /* Creates dummy elements. */
    struct fp_table_value dummy_fp_table_value;
    dummy_fp_table_value.file = file;

    struct s_page dummy_paddr_table_value;
    dummy_paddr_table_value.vaddr = vaddr;

    lock_acquire(&fp_table_lock);
    struct hash *share_table_paddr = hash_entry(hash_find(&share_table_fp, &dummy_fp_table_value.hash_elem),
        struct fp_table_value, hash_elem)->share_table;
    struct hash_elem *e = hash_delete(share_table_paddr, &dummy_paddr_table_value.share_elem);
    lock_release(&fp_table_lock);
    return e != NULL;
}

/* Destroys and frees the inner share table. */
static void
inner_table_destroy (struct hash_elem *hash_elem, void *aux UNUSED) {
    struct fp_table_value *inner_share_table = hash_entry(hash_elem, struct fp_table_value, hash_elem);
    hash_destroy(inner_share_table->share_table, NULL);
    free(inner_share_table->share_table);
    free(inner_share_table);
}

/*Destroys entire share table.*/
void
share_table_destroy (void) {
    lock_acquire(&fp_table_lock);
    hash_destroy(&share_table_fp, inner_table_destroy);
    lock_release(&fp_table_lock);
}

static unsigned
share_table_fp_hash_func (const struct hash_elem *element, void *aux UNUSED) {
    return hash_ptr(hash_entry(element, struct fp_table_value, hash_elem)->file);
}

static bool
share_table_fp_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
    const unsigned a_ = (unsigned) hash_entry(a, struct fp_table_value, hash_elem)->file;
    const unsigned b_ = (unsigned) hash_entry(b, struct fp_table_value, hash_elem)->file;
    return a_ < b_;
}

static unsigned
spage_hash_func (const struct hash_elem *element, void *aux UNUSED) {
    return hash_ptr(hash_entry(element, struct s_page, share_elem)->vaddr);
}

static bool
spage_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
    const unsigned a_ = (unsigned) hash_entry(a, struct s_page, share_elem)->vaddr;
    const unsigned b_ = (unsigned) hash_entry(b, struct s_page, share_elem)->vaddr;
    return a_ < b_;
}