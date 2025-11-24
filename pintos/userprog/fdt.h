#ifndef USERPROG_FDT_H
#define USERPROG_FDT_H

#include "threads/thread.h"

bool open_fdt_entry(struct fdt_entry **fdt_entry, int fd, struct file *file);
void close_fdt_entry(struct fdt_entry **table, int fd);
bool increase_fdt_size(struct thread *t, int fd);
bool dup_fdt_entry(struct fdt_entry *parent_ent, struct fdt_entry **child_ent);
bool fork_fdt(struct thread *parent, struct thread *child);

#endif /* USERPROG_FDT_H */
