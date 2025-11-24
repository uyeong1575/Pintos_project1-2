#include "userprog/fdt.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include <string.h>

/* file_lock is defined in syscall.c. */
extern struct lock file_lock;

/* file 받아서 fd 자리에 fdt_entry 만들기 */
bool 
open_fdt_entry(struct fdt_entry **fdt_entry, int fd, struct file *file){

	if(fdt_entry == NULL || file == NULL)
		return false;

	struct fdt_entry *entry = calloc(1, sizeof(struct fdt_entry));
	if(entry == NULL)
		return false;

	fdt_entry[fd] = entry;
	fdt_entry[fd]->fdt = file;
	fdt_entry[fd]->ref_cnt = 1;
	fdt_entry[fd]->type = FILE;

	return true;
}


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

	/* 2^n 값 구하기 */
	int need = fd + 1;
	int new_size = old_size ? old_size : 1;
	while (new_size < need)
		new_size <<= 1;

	struct fdt_entry **old_entry = t->fdt_entry;
	if (old_entry == NULL)
		return false;

	/* 새 버퍼를 0으로 초기화, 기존 내용을 복사 */
	struct fdt_entry **new_entry = calloc(new_size, sizeof(struct fdt_entry*));
	if (new_entry == NULL)
		return false;
	memcpy(new_entry, old_entry, old_size * sizeof(struct fdt_entry*));

	t->fdt_entry = new_entry;
	t->FD_TABLE_SIZE = new_size;

	free(old_entry);

	return true;
}

/* parent 엔트리 깊은 복사 해서 child에 연결 */
/* FILE일 경우만 dup, STDIN/STDOUT 이면 그냥 만들기*/
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

/* 부모 fdt_entry배열 fork*/
bool
fork_fdt(struct thread *parent, struct thread *child){
	for (int i = 0; i < parent->FD_TABLE_SIZE; i++) {
		struct fdt_entry *p_entry = parent->fdt_entry[i];
		if (p_entry == NULL)
			continue;

		/* 부모에서 같은 엔트리를 공유한 fd라면 자식도 동일 포인터 공유 */
		bool dup_find = false;
		if(p_entry->ref_cnt >= 2){
			for (int j = 0; j < i; j++) {
				if (parent->fdt_entry[j] == p_entry) {
					child->fdt_entry[i] = child->fdt_entry[j];
					dup_find = true;
					break;
				}
			}
		}
		/* dup 연결 했으면 만들기 생략 */
		if (dup_find)
			continue;

		if (!dup_fdt_entry(p_entry, &child->fdt_entry[i]))
			return false;
	}

	return true;
}
