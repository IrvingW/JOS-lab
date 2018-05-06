#include <inc/lib.h>
#include <inc/env.h>

void umain(int argc, char **argv)
{
	int i;
	int n = 3;
	for (i = 0; i < n; i++) {
		cprintf("[%08x] Normal Priority Env is Running\n", sys_getenvid());
	}
	return;
}