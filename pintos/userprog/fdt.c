#include "userprog/fdt.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include <string.h>

/* file_lock is defined in syscall.c. */
extern struct lock file_lock;

/* ref_cnt 기준으로 파일 닫기 */
void
close_fdt_entry(struct fdt_entry **table, int fd){
	struct fdt_entry *ent = table[fd];
	if (ent == NULL)
		return;
		
	table[fd] = NULL;
	ent->ref_cnt--;
	if (ent->type == FILE && ent->fdt != NULL) {
		if (ent->ref_cnt == 0) {
			lock_acquire(&file_lock);
			file_close(ent->fdt);
			lock_release(&file_lock);
		}
	}
	if (ent->ref_cnt == 0)
		free(ent);
}

/* 2^n 크기로 확장, 새 슬롯을 0으로 채우기 */
bool
increase_fdt_size(struct thread *t, int fd) {
	int old_size = t->FD_TABLE_SIZE;
	if (fd < old_size)
		return true;

	int need = fd + 1;
	int new_size = old_size ? old_size : 1;
	while (new_size < need)
		new_size <<= 1;

	struct fdt_entry **new_entry = realloc(t->fdt_entry, new_size * sizeof(struct fdt_entry*));
	if (new_entry == NULL)
		return false;

	memset(new_entry + old_size, 0, (new_size - old_size) * sizeof(struct fdt_entry*));
	t->fdt_entry = new_entry;
	t->FD_TABLE_SIZE = new_size;
	return true;
}

/* parent 엔트리를 깊이 복제하여 dst_slot에 채운다. */
bool
dup_fdt_entry(struct fdt_entry *parent_ent, struct fdt_entry **child_ent){
	if (parent_ent == NULL || child_ent == NULL)
		return false;

	struct fdt_entry *entry = calloc(1, sizeof(struct fdt_entry));
	if(entry == NULL)
		return false;

	entry->type = parent_ent->type;
	entry->ref_cnt = parent_ent->ref_cnt;

	if(parent_ent->type == FILE){
		lock_acquire(&file_lock);
		struct file *dup = file_duplicate(parent_ent->fdt);
		lock_release(&file_lock);
		if (dup == NULL){
			free(entry);
			return false;
		}
		entry->fdt = dup;
	}

	*child_ent = entry;
	return true;
}
