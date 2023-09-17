#include <stdio.h>
#include <unistd.h>
#include <execinfo.h>
#include "includes/utils.h"
#include <signal.h>

int called = 0;

#define NCALLS 2
void a(void) {
	sleep(NCALLS);
}
void my_sleep(void) {
	printf("We've slept for: %d seconds\n", NCALLS*called);
	called++;
	a();
}

int main(void) {
	while (1) {
		//printf("%d: %d\n", global++, getpid());
		print_pid(getpid());
		my_sleep();
    	//sleep_one();
	}
	
	return 0;
}
