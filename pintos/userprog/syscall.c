#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "include/threads/init.h"

#include "threads/synch.h"
#include "include/filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);


static void vaild_get_addr(void *addr);
static void vaild_get_buffer(char *addr, unsigned length);
static void vaild_put_addr(char *addr, unsigned length);

//syscall 함수화
static bool sys_create(const char *file, unsigned initial_size);
static bool sys_remove(const char *file);
static int sys_open(const char *file);
static int sys_filesize(int fd);

static int sys_read(int fd, void *buffer, unsigned length);
static int sys_write(int fd, void *buffer, unsigned length);

static void sys_exit(int status);

struct lock file_lock;

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

static int64_t
get_user (const uint8_t *uaddr) {
    int64_t result;

    if (uaddr == NULL || !is_user_vaddr (uaddr))
        return -1;

    __asm __volatile (
        "movabsq $done_get, %0\n"
        "movzbq %1, %0\n"
        "done_get:\n"
        : "=&a" (result) : "m" (*uaddr));
    return result;
}

static bool
put_user (uint8_t *udst, uint8_t byte) {
    int64_t error_code;

    if (udst == NULL || !is_user_vaddr (udst))
        return false;

    __asm __volatile (
        "movabsq $done_put, %0\n"
        "movb %b2, %1\n"
        "done_put:\n"
        : "=&a" (error_code), "=m" (*udst) : "q" (byte));
    return error_code != -1;
}


void
syscall_init (void) {

	lock_init(&file_lock);

	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	// System call number is in rax
	int syscall_num = f->R.rax;

	switch (syscall_num) {

		case SYS_HALT:
            power_off();
            break;

		case SYS_EXIT:
			sys_exit(f->R.rdi);
			break;



		case SYS_CREATE:
			f->R.rax = sys_create(f->R.rdi, f->R.rsi);
			break;

		case SYS_REMOVE:
			f->R.rax = sys_remove(f->R.rdi);
			break;

		case SYS_OPEN:
			f->R.rax = sys_open(f->R.rdi);
			break;

		case SYS_FILESIZE:
			f->R.rax = sys_filesize(f->R.rdi);
			break;

		case SYS_READ:
			f->R.rax = sys_read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;

		case SYS_WRITE:
			f->R.rax = sys_write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;

		case SYS_SEEK:

			break;

		case SYS_TELL:

			break;


		case SYS_CLOSE:
			break;

		default:
			printf("system call! (unimplemented syscall number: %d)\n", syscall_num);
			thread_exit();
			break;
	}
}


static void vaild_get_addr(void *addr){
	if(get_user(addr) < 0)
		sys_exit(-1);
}

static void vaild_get_buffer(char *addr, unsigned length){
	for (unsigned i = 0; i < length; i++){
		if(get_user(addr+i) < 0)
			sys_exit(-1);
	}
}

static void vaild_put_addr(char *addr, unsigned length){

	/* 나중에 put_user로 구현*/
	for (unsigned i = 0; i < length; i++){
		if(put_user(addr+i, 0) == 0)
			sys_exit(-1);
	}

}

/* file create 성공시 true*/
static bool sys_create(const char *file, unsigned initial_size){

	vaild_get_addr(file);

	lock_acquire(&file_lock);
	bool success = filesys_create(file, initial_size);
	lock_release(&file_lock);
	return success;
}

static bool sys_remove(const char *file){
	vaild_get_addr(file);

	lock_acquire(&file_lock);
	bool success = filesys_remove(file);
	lock_release(&file_lock);
	return success;
}

static int sys_open(const char *file){
	vaild_get_addr(file);
	struct thread *curr = thread_current();
	lock_acquire(&file_lock);

	struct file *open_file = filesys_open(file);
	if (open_file == NULL){
		lock_release(&file_lock);
		return -1;
	}

	int fd = curr->fdtable->fd_checkp;
	while (curr->fdtable->fdt[fd] != NULL){
		fd++;
		if(fd > MAXNUM_FDT){
			//sys_close(file);
			lock_release(&file_lock);
			return -1;
		}
	}

	curr->fdtable->fdt[fd] = open_file;
	curr->fdtable->fd_checkp = fd + 1; //fd_check point 업데이트
	lock_release(&file_lock);
	return fd;
}

/* 실패시 뭐 반환 이런거 없길래 일단 검증 안함*/
static int sys_filesize(int fd){

	struct file *file = thread_current()->fdtable->fdt[fd];
	return file_length(file);
}


static int sys_read(int fd, void *buffer, unsigned length){

	vaild_put_addr(buffer, length);
	if(fd < 0 || fd > MAXNUM_FDT)
		return -1;

	lock_acquire(&file_lock);

	/* fd에서 buffer로 length만큼 복사?*/
	/* 읽은 바이트 수 반환 : EOF면 0, 실패 시 -1*/
	/* fd가 0이면 키보드에서 읽어라*/

	if(fd == 0){
		input_getc();
		lock_release(&file_lock);
	}
	else{
		/* fd에 해당하는 파일에서 length만큼 읽어서 buffer에 담음*/
		struct file *file = thread_current()->fdtable->fdt[fd];
		if(file == NULL){
			lock_release(&file_lock);
			return -1;
		}
		int size = file_read_at(file, buffer, length, 0); //처음부터 읽어라
		lock_release(&file_lock);
		return size;
	}
}

static int sys_write(int fd, void *buffer, unsigned length) {

	vaild_get_buffer(buffer, length);
	if(fd < 0 || fd > MAXNUM_FDT)
		return -1;

	lock_acquire(&file_lock);
	// For now, only handle writing to stdout (fd = 1)
	if (fd == 1) {
		putbuf(buffer, length);  // Write to console
		lock_release(&file_lock);
		return length;         // Return number of bytes written
	} else {
		/* file에 write*/
		struct file *file = thread_current()->fdtable->fdt[fd];
		off_t size = file_write(file, buffer, length);
		lock_release(&file_lock);
		return size;   
	}
}

static void sys_exit(int status){
	thread_current()->exit_status = status;
	thread_exit();
}