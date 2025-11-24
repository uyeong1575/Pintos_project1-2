#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

#include "include/threads/synch.h"
#include "userprog/fdt.h"
#include <list.h>

static void process_cleanup (void);
static void set_initd_stdio (struct thread *t);
static bool load (const char **argv, int argc, struct intr_frame *if_);
static void initd (void *aux);
static void __do_fork (void *);

extern struct lock file_lock;

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *curr = thread_current ();
	/* 프로세스에 필요한 구조체 여기서 만들어야함.*/

	/* fdt entry 포인터 배열 할당 */
	curr->fdt_entry = calloc(curr->FD_TABLE_SIZE, sizeof(struct fdt_entry*));
	if (curr->fdt_entry == NULL)
        PANIC("Failed to allocate file descriptor table");
}

/* initd 처음 STDIN/STDOUT 세팅, (이후 fork는 부모 따라가도록) */
static void
set_initd_stdio (struct thread *t) {
	struct fdt_entry *f0 = calloc(1, sizeof(struct fdt_entry));
	if (f0 == NULL)
		PANIC("Failed to initd STDIN setting");

	struct fdt_entry *f1 = calloc(1, sizeof(struct fdt_entry));
	if (f1 == NULL) {
		free(f0);
		PANIC("Failed to initd STDOUT setting");
	}
	t->fdt_entry[0] = f0;
	t->fdt_entry[0]->type = STDIN;
	t->fdt_entry[0]->ref_cnt = 1;

	t->fdt_entry[1] = f1;
	t->fdt_entry[1]->type = STDOUT;
	t->fdt_entry[1]->ref_cnt = 1;
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */

struct initd_arg{
	char *fn_copy;
	struct child *c;
};

tid_t
process_create_initd (const char *file_name) {

	struct thread *parent = thread_current ();
    struct child *c = calloc (1, sizeof(struct child));
    if (c == NULL)
        return TID_ERROR;

    struct initd_arg *initd_arg = calloc (1, sizeof(struct initd_arg));
    if (initd_arg == NULL){
		free(c);
		return TID_ERROR;
	}

	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL){
		free(c);
		free(initd_arg);
		return TID_ERROR;
	}
	strlcpy (fn_copy, file_name, PGSIZE);

	//thread에 file_name만 전달하도록
	//이 과정은 단순 이름 전달 용도임, 보존이 의미가 없음 이미 fn_copy로 보존함
	char* save_ptr;
	file_name = strtok_r (file_name, " ", &save_ptr);

	/* initd 인자 전달 세팅 */
	initd_arg->fn_copy = fn_copy;
	initd_arg->c = c;

	sema_init(&c->wait_sema, 0);	// 먼저 sema_init 해야함!!

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (file_name, PRI_DEFAULT, initd, initd_arg);
	if (tid == TID_ERROR){
		palloc_free_page (fn_copy);
		free(c);
		free(initd_arg);
		return TID_ERROR;
	}

	// 자식(initd) 구조체 필드 채우고 부모(main) list에 등록
	c->child_tid = tid;
	c->exit_status = -1;
	c->waited = false;
	list_push_back(&parent->child_list, &c->child_elem);

	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *aux) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	/* initd 스레드의 child 구조체 생성 */
	struct initd_arg *i = aux;
    struct child *child = i->c;
    char *file_name = i->fn_copy;
    free(i);	// aux로 전달된 구조체 free

	//exit시 child_info 접근(sema_up, exit_status) 하기 때문에 여기서 해야함
	thread_current()->child_info = child;
	thread_current()->FD_TABLE_SIZE = 128; // 초기(initd) fdt size 128 세팅

	process_init();

	set_initd_stdio(thread_current());

	if (process_exec (file_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

struct forkarg {
	struct intr_frame *f;
	struct thread *t;
	struct semaphore forksema;
	struct child *c;
	bool success;
};

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_) {

	struct forkarg *fork = calloc(1, sizeof(struct forkarg));
	if (fork == NULL)
        return TID_ERROR;
	// 자식 구조체 생성
	struct child *c = calloc(1, sizeof(struct child));
	if (c == NULL){
		free(fork);
		return TID_ERROR;
	}
	fork->f = if_;
	fork->t = thread_current();
	fork->c = c;
	sema_init(&fork->forksema, 0); //__do_fork 결과 확인용
	sema_init(&c->wait_sema, 0); // create전에 init 해야함

	/* Clone current thread to new thread.*/
	tid_t tid = thread_create (name, PRI_DEFAULT, __do_fork, fork);
	if(tid == TID_ERROR){
		/* 자원 해제 */
		free(fork);
		free(c);
		return TID_ERROR;
	}

	// 자식 구조체 필드 채우고 부모 list에 등록
	c->child_tid = tid;
	c->exit_status = -1;
	c->waited = false;
	list_push_back(&thread_current()->child_list, &c->child_elem);

	// __do_fork 결과 확인용
	sema_down(&fork->forksema);

	if(fork->success){
		free(fork);
		return tid;
	}
	else{
		// 실패 시 free하고 반환
		free(fork);
		list_remove(&c->child_elem);
		free(c);
		return TID_ERROR;
	}
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
/* 부모의 각 유저 PTE를 자식에게 복제.*/
/* 1. aux로 받은 부모 스레드의 pml4에서 va 대응 물리 페이지를 pml4_get_page로 구해온다
	(커널 페이지라면 건너 뛰기)
   2. 자식용 유저페이지를 새로 할당. 부모 페이지 내용을 복사
   3. 부모 PTE의 writable 비트에 따라 writeable 설정
   4. 자식의 pml4에 pml4_set_page(current->pml4, va, newpage, writable)
   	  로 매핑. 실패 시 할당 해제 등 처리.*/

/* pte : va를 가리키는 페이지테이블 엔트리 포인터(물리 페이지 주소 + 플래그가 담김) */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	if(is_kern_pte(pte))
		return true;	// 커널 매핑이면 false 반환이 아니라 건너 뛰어야함.

	/* 2. Resolve VA from the parent's page map level 4. */
	/* pml4에서 va가 가리키는 물리주소와 매핑된 커널 가상주소(물리주소+KERN_BASE) 반환.*/
	parent_page = pml4_get_page (parent->pml4, va);

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	newpage = palloc_get_page(PAL_USER | PAL_ZERO);
	if(newpage == NULL)
		return false;

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	memcpy(newpage, parent_page, PGSIZE);

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	writable = is_writable(pte);
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		palloc_free_page(newpage);
		return false;
		/* 6. TODO: if fail to insert page, do error handling. */
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux) {
	struct forkarg *args = aux;
	struct intr_frame if_;
	struct thread *parent = (struct thread *) args->t;
	struct thread *current = thread_current ();

	current->FD_TABLE_SIZE = parent->FD_TABLE_SIZE;
	current->child_info = args->c;

	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if = args->f;
	bool succ = true;

	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));

	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	/*  주어진 pml4에 존재하는 모든 페이지 테이블 엔트리를 순회하며 func 호출
		func가 false를 리턴하면 멈추고 false 리턴*/
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/

	process_init();

	/* dup는 바꾸면 안된다. */
	/* fdt 복제 */
	for (int i = 0; i < parent->FD_TABLE_SIZE; i++) {
		struct fdt_entry *p_entry = parent->fdt_entry[i];
		if (p_entry == NULL)
			continue;

		/* 부모에서 같은 엔트리를 공유한 fd라면 자식도 동일 포인터 공유 */
		bool dup_find = false;
		if(p_entry->ref_cnt >= 2){
			for (int j = 0; j < i; j++) {
				if (parent->fdt_entry[j] == p_entry) {
					current->fdt_entry[i] = current->fdt_entry[j];
					dup_find = true;
					break;
				}
			}
		}
		/* dup 연결 했으면 만들기 생략 */
		if (dup_find)
			continue;

		if (!dup_fdt_entry(p_entry, &current->fdt_entry[i]))
			goto error;
	}

	/* Finally, switch to the newly created process. */
	if (succ){
		args->success = true;
		if_.R.rax = 0;	//자식은 0 반환
		sema_up(&args->forksema);
		do_iret (&if_);
	}
error:
	args->success = false;
	sema_up(&args->forksema);
	thread_exit ();
}

/* load the arguments to the stack */
void load_arguments_to_stack(struct intr_frame *if_, char ** argv, int argc) {

    uint8_t *rsp = if_->rsp;
    char *arg_addresses[argc];  // 각 인자의 주소를 저장할 배열

        // 1. 먼저 문자열 데이터를 스택에 푸시 (역순으로)
    for (int i = argc - 1; i >= 0; i--) {
        int len = strlen(argv[i]) + 1;  // null terminator 포함
        rsp -= len;
        memcpy(rsp, argv[i], len);
        arg_addresses[i] = (char *)rsp;  // 이 주소를 저장
    }


    // 2. Word-align
    while ((uintptr_t)rsp % 8 != 0) {
        rsp--;
        *rsp = 0;  // 패딩
    }

     // 3. argv[argc] = NULL 추가
    rsp -= sizeof(char *);
    *(char **)rsp = 0;

    // 4. address stack에 추가
    for (int i = argc - 1; i >= 0; i--) {
        rsp -= sizeof(char *);
        *(char **)rsp = arg_addresses[i];
    }

    // 5. rsi 저장 + return address 0 으로 추가
    uint64_t rsi_value = (uint64_t)rsp;
    rsp -= sizeof(void *);
    *(char **)rsp = 0;

    // 6. rdi + rsi 저장 + rsp 업데이트
    if_->R.rdi = argc;
    if_->R.rsi = rsi_value;
    if_->rsp = rsp;

}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *f_name) {
	bool success;
	// argv[0] = 프로그램 이름
	char *argv[128];
	int argc = 0;

	char *token, *save_ptr;
	for (token = strtok_r(f_name, " ", &save_ptr); token != NULL;
		 token = strtok_r(NULL, " ", &save_ptr))
	{
		argv[argc++] = token;
	}

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup ();
	/* And then load the binary */
	success = load (argv, argc, &_if);

	/* If load failed, quit. */
	palloc_free_page (f_name);
	if (!success) {
		return -1;
	}

	/* Start switched process. */
	do_iret (&_if);
	NOT_REACHED ();
}


/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */

/* TID인 스레드가 죽을때까지 기다리기 그리고 그 자식의 exit status를 반환
	자식이 커널에 의해 종료된 경우 -1 반환
	TID가 유효하지 않거나, 자식이 아니거나,
	주어진 TID에 대해 process_wait()가 이미 성공적으로 호출된 경우 -1을 반환*/
int
process_wait (tid_t child_tid UNUSED) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */

	struct thread *curr = thread_current();
	struct child *target = NULL;

	for (struct list_elem *e = list_begin(&curr->child_list); e != list_end(&curr->child_list); e = list_next(e))
	{
		struct child *c = list_entry(e, struct child, child_elem);
		if (c->child_tid == child_tid) {
			target = c;
			break;
		}
	}

	// 자식이 아니거나, 이미 wait 호출한 자식이면
	if(target == NULL || target->waited == true)
		return -1;

	target->waited = true;
	sema_down(&target->wait_sema);

	int exit_status = target->exit_status;	//커널에 의해 강제 종료된 경우는 -1이 들어있음

	/* child 구조체 free */
	list_remove(&target->child_elem);
	free(target);

	return exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */

	/* fdt 초기화 */
	if (curr->fdt_entry != NULL) {
		for(int i = 0; i < curr->FD_TABLE_SIZE; i++){
			// entry가 있으면
			if (curr->fdt_entry[i] != NULL){
				close_fdt_entry(curr->fdt_entry, i);
			}
		}
		free(curr->fdt_entry);
	}

	process_cleanup ();

	if (curr->executable) {
	    lock_acquire(&file_lock);
        file_allow_write(curr->executable);
        file_close(curr->executable);
        lock_release(&file_lock);
	}

	/* child_list 순회하면서 정리 필요, 자식보다 부모가 먼저 죽으면 */
	struct list_elem *e = list_begin(&curr->child_list);
	while(e != list_end(&curr->child_list)){
		e = list_remove(e);
		continue;
	}

	/* child_info 없으면 그냥 exit하면 됨 */
	if (curr->child_info){
		curr->child_info->exit_status = curr->exit_status;
		printf("%s: exit(%d)\n", curr->name, curr->exit_status);
		sema_up(&curr->child_info->wait_sema);
	}
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char **argv, int argc, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	/* Open executable file. */
	file = filesys_open (argv[0]);

	if (file == NULL) {
		printf ("load: %s: open failed\n", argv[0]);
		goto done;
	}

	file_deny_write(file);
	t->executable = file;

	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", argv[0]);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */
	load_arguments_to_stack(if_, argv, argc);


	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	if (!success) {
        file_close(file);
        t->executable = NULL;
    }
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */
