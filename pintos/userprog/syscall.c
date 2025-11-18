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


static void valid_get_addr(void *addr);
static void valid_get_buffer(char *addr, unsigned length);
static void valid_put_addr(char *addr, unsigned length);

//syscall 함수화
static bool sys_create(const char *file, unsigned initial_size);
static bool sys_remove(const char *file);
static int sys_open(const char *file);
static int sys_filesize(int fd);
static int sys_read(int fd, void *buffer, unsigned length);
static int sys_write(int fd, void *buffer, unsigned length);
static void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
static void sys_close(int fd);
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
			sys_seek(f->R.rdi, f->R.rsi);
			break;

		case SYS_TELL:
			f->R.rax = sys_tell(f->R.rdi);
			break;

		case SYS_CLOSE:
			//sys_close(f->R.rdi);
			break;

		default:
			printf("system call! (unimplemented syscall number: %d)\n", syscall_num);
			thread_exit();
			break;
	}
}

/* user 포인터 검사 */
static void valid_get_addr(void *addr){
	if(get_user(addr) < 0)
		sys_exit(-1);
}

/* user 버퍼 검사 */
static void valid_get_buffer(char *addr, unsigned length){

	char *end = addr + length -1;
	if(get_user(addr) < 0 || get_user(end) < 0)
			sys_exit(-1);
	
}

static void valid_put_addr(char *addr, unsigned length){

	char *end = addr + length -1;
	if(put_user(addr, 0) == 0 || put_user(end, 0) == 0)
		sys_exit(-1);
}

static bool sys_create(const char *file, unsigned initial_size){

	valid_get_addr(file);

	lock_acquire(&file_lock);
	bool success = filesys_create(file, initial_size);
	lock_release(&file_lock);
	return success;
}

static bool sys_remove(const char *file){
	valid_get_addr(file);

	lock_acquire(&file_lock);
	bool success = filesys_remove(file);
	lock_release(&file_lock);
	return success;
}

static int sys_open(const char *file){
    valid_get_addr(file);

    struct file **fd_table = thread_current()->fd_table;
    lock_acquire(&file_lock);
    struct file *opened_file = filesys_open(file);
    if (opened_file == NULL) {
		/* open 실패면 inode close, free(file) 해줌 */
        lock_release(&file_lock); 
        return -1;
    }

    int res = -1;
    for (size_t i = 2; i < FD_TABLE_SIZE; i++) {
        if(fd_table[i] == NULL){
            fd_table[i] = opened_file;
            res = i;
            break;
        }
    }

    // No free descriptors - close the file
    if (res == -1) {
        file_close(opened_file);
    }

    lock_release(&file_lock);

    return res;
}

static void sys_close(int fd)
{
	//fd 범위 검증
	if(fd<2 || fd>=FD_TABLE_SIZE)
	{
		sys_exit(-1);
	}

	struct file **fd_table = thread_current()->fd_table;
	if(fd_table == NULL || fd_table[fd]==NULL)
	{
		sys_exit(-1);
	}

	lock_acquire(&file_lock);
	file_close(fd_table[fd]);
	fd_table[fd]=NULL;			//fd 재사용 가능
	lock_release(&file_lock);
}


static int sys_filesize(int fd){
    // Validate fd range
    if (fd < 0 || fd >= FD_TABLE_SIZE)
        return -1;


    struct file **fd_table = thread_current()->fd_table;
    if (fd_table == NULL)
        return -1;


    struct file *f = fd_table[fd];
    if (f == NULL)
        return -1;

	lock_acquire(&file_lock);
    int size = file_length(f);
    lock_release(&file_lock);

    return size;
}

static int sys_read(int fd, void *buffer, unsigned length){

	if(length == 0)
		return 0;

	valid_put_addr(buffer, length); //써보면서 확인해야함
	if(fd < 0 || fd > FD_TABLE_SIZE || fd == 1)
		return -1;

	if(fd == 0){
       for (unsigned i = 0; i < length; i++) {
            uint8_t c = input_getc();
            // 쓰기 시
            // buffer + i 주소에 c를 쓰기
            if(!put_user((uint8_t *)buffer + i, c))
                return i;  // 실패시 지금까지 읽은 바이트 수 반환
		}
	}
	else{
		/* fd에 해당하는 파일에서 length만큼 읽어서 buffer에 담음*/
		struct file *file = thread_current()->fd_table[fd];
		if(file == NULL){
			return -1;
		}
		lock_acquire(&file_lock);
		/* file_reat_at 필요시 변경할지도 */
		int size = file_read(file, buffer, length);
		lock_release(&file_lock);
		return size;
	}
}

static int sys_write(int fd, void *buffer, unsigned length) {

	valid_get_buffer(buffer, length); //읽기(접근) 가능을 확인해야함
	if(fd <= 0 || fd > FD_TABLE_SIZE) //0(stdin) 불가능 1~127까지 가능해야함
		return -1;

	if (fd == 1) {
		/* stdout으로 write*/
		putbuf(buffer, length);  // Write to console
		return length;         // Return number of bytes written
	} else {
		/* file에 write*/
		struct file *file = thread_current()->fd_table[fd];
		if(file == NULL)
			return -1;
		lock_acquire(&file_lock);
		off_t size = file_write(file, buffer, length);
		lock_release(&file_lock);
		return size;   
	}
}

/* 반환값이 없으면 문제 생기면 그냥 exit 시킨다. */
static void sys_seek(int fd, unsigned position) {

	if(fd < 2 || fd > FD_TABLE_SIZE)
		sys_exit(-1);

	struct file *file = thread_current()->fd_table[fd];
	if(file == NULL)
		sys_exit(-1);

	lock_acquire(&file_lock);
	file_seek(file, position);
	lock_release(&file_lock);
}

unsigned sys_tell(int fd){

	if(fd < 2 || fd > FD_TABLE_SIZE)
		return -1;

	struct file *file = thread_current()->fd_table[fd];
	if(file == NULL)
		return -1;

	lock_acquire(&file_lock);
	unsigned size = file_tell(file);
	lock_release(&file_lock);
	return size;
}

static void sys_exit(int status){
	thread_current()->exit_status = status;
	thread_exit();
}
