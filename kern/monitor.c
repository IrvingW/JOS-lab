// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "backtrace", "Display information about the current stack backtrack", mon_backtrace },
	{ "time", "Display the run time of a special command", mon_time },
};
#define NCOMMANDS (sizeof(commands)/sizeof(commands[0]))

unsigned read_eip();

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < NCOMMANDS; i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		(end-entry+1023)/1024);
	return 0;
}

// Lab1 only
// read the pointer to the retaddr on the stack
static uint32_t
read_pretaddr() {
    uint32_t pretaddr;
    __asm __volatile("leal 4(%%ebp), %0" : "=r" (pretaddr)); 
    return pretaddr;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	// Your code here.
	uint32_t ebp = read_ebp();
	cprintf("Stack backtrace:\n");
	uint32_t eip;
	while(ebp != 0x0){		// the ebp register is initialize with 0x0 in entry.S
		eip = *((uint32_t*)ebp + 1);
		uint32_t first_arg = *((uint32_t*)ebp + 2);
		uint32_t second_arg = *((uint32_t*)ebp + 3);
		uint32_t third_arg = *((uint32_t*)ebp + 4);
		uint32_t fourth_arg = *((uint32_t*)ebp + 5);
		uint32_t fifth_arg = *((uint32_t*)ebp + 6);
		cprintf("  eip %08x  ebp %08x  args %08x %08x %08x %08x %08x\n", 
			eip, ebp, first_arg, second_arg, third_arg, fourth_arg, fifth_arg );

		// debug info, exercise 14
		struct Eipdebuginfo e;
		if(debuginfo_eip(eip, &e) == 0){	// success find debug info
			char func_name[e.eip_fn_namelen + 1];	// str end with '\0'
			int i;
			for(i = 0; i < e.eip_fn_namelen; i++){
				func_name[i] = e.eip_fn_name[i];
			}
			func_name[e.eip_fn_namelen] = '\0';
			cprintf("         %s:%d: %s+%x\n", e.eip_file, e.eip_line, func_name, eip - e.eip_fn_addr);
		}
		ebp = *((uint32_t*)ebp);	// set old ebp
	}
    cprintf("Backtrace success\n");
	return 0;
}

static uint64_t
rdtsc(){
	unsigned int lo, hi;
	__asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d"(hi));
	return ((uint64_t)hi << 32) | lo;
}

int 
mon_time(int argc, char**argv, struct Trapframe *tf){
	if(argc == 1){
		cprintf("Please enter a command after \"time\"\n");
		return 0;
	}
	int i;
	// search for the input command
	for(i = 0; i < NCOMMANDS; i++){
		if(strcmp(argv[1], commands[i].name) == 0)	// find a command
			break;
		if(i == NCOMMANDS-1){	// unknown command
			cprintf("Unknown command after time %s\n", argv[1]);
			return 0;
		}
	}
	// remove arg "time"
	argc --;
	argv ++;
	uint64_t start_time = rdtsc();
	commands[i].func(argc, argv, tf);
	uint64_t end_time = rdtsc();
	cprintf("Kerninfo cycles: %08d\n", end_time - start_time);
	return 0;
}



/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < NCOMMANDS; i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");

	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}

// return EIP of caller.
// does not work if inlined.
// putting at the end of the file seems to prevent inlining.
unsigned
read_eip()
{
	uint32_t callerpc;
	__asm __volatile("movl 4(%%ebp), %0" : "=r" (callerpc));
	return callerpc;
}
