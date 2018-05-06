#include <inc/lib.h>
#include <inc/env.h>

void umain(int argc, char **argv)
{
	sys_env_set_priority(0, SUPER_PRIORITY);
	int i;
	int n = 3;
	for (i = 0; i < n; i++) {
		cprintf("[%08x] Super Priority Env is Running\n", sys_getenvid());
	}
	return;
}