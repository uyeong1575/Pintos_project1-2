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
static void vaild_put_addr(void *addr, unsigned length);

//syscall 함수화
static bool sys_create(const char *file, unsigned initial_size);
static bool sys_remove(const char *file);
static int sys_write(int fd, void *buffer, unsigned length);
static int sys_open(const char *file);
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

/* todo : 지금 주소 저장 할지 말지*/
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

			break;

		case SYS_READ:

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
	if(is_kernel_vaddr(addr) || addr == NULL)
		sys_exit(-1);
	if(get_user(addr) < 0)
		sys_exit(-1);
}

static void vaild_put_addr(void *addr, unsigned length){
	if(is_kernel_vaddr(addr) || addr == NULL)
		sys_exit(-1);

	/* 나중에 put_user로 구현*/
}

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

static int sys_write(int fd, void *buffer, unsigned length){

	/* todo : buffer valid*/

	// For now, only handle writing to stdout (fd = 1)
	if (fd == 1) {
		putbuf(buffer, length);  // Write to console
		return length;         // Return number of bytes written
	} else {
		return -1;           // Error: unsupported fd
	}

}

// should create a new file descriptor
static int sys_open(const char *file){
    vaild_get_addr(file);

    struct file **fd_table = thread_current()->fd_table;
        lock_acquire(&file_lock);
        struct file *opened_file = filesys_open(file);
        lock_release(&file_lock);

        if (opened_file == NULL) {
            return -1;
        }


        for (size_t i = 2; i < FD_TABLE_SIZE; i++) {
            if(fd_table[i] == NULL){
                fd_table[i] = opened_file;
                return i;
            }
        }

        // No free descriptors - close the file
        lock_acquire(&file_lock);
        file_close(opened_file);
        lock_release(&file_lock);

    return -1;
}

static void sys_exit(int status){
	thread_current()->exit_status = status;
	thread_exit();
}
