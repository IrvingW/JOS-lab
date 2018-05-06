#include <inc/lib.h>
#include <inc/env.h>

void umain(int argc, char **argv)
{
	int r = sys_env_set_priority(0, HIGH_PRIORITY);
	if(r < 0){
		cprintf("[%08x] Not in prioriry schedule mode!\n", sys_getenvid());
		return;
	}
	int i;
	int n = 3;
	for (i = 0; i < n; i++) {
		cprintf("[%08x] High Priority Env is Running\n", sys_getenvid());
	}
	return;
}