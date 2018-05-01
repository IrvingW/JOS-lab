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
#include <kern/trap.h>
#include <kern/pmap.h>

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
	{ "shmap", "Display the physical page mappings and corresponding permission bits that apply to the pages between input addresses.", mon_shmap },
	{ "chmap", "Explicitly set, clear, or change the permissions of any mapping in the current address space.", mon_chmap },
	{ "memdump", "Dump the contents of a range of memory given either a virtual or physical address range.", mon_memdump },
	{ "c", "continue execution", mon_c },
	{ "si", "execute single instruction", mon_si },
	{ "x", "display the memory", mon_x },
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

static uint32_t
hex2int(char * s){
	int index = 0;
	uint32_t result = 0;
	if(s[0] != '0' || s[1] != 'x'){
		return 0;
	}
	index = 2;
	while(s[index] != '\0'){
		result *= 16;
		if(s[index] >= '0' && s[index] <= '9'){
			result += s[index] - '0';
		}
		else if(s[index] >= 'a' && s[index] <= 'f'){
			result += (s[index] - 'a' + 10);
		}
		else if(s[index] >= 'A' && s[index] <= 'F'){
			result += (s[index] - 'A' + 10);
		}
		else{ 
			return 0;
		}
		index ++;
	}
	return result;
}

int
mon_shmap(int argc, char**argv, struct Trapframe *tf){
	if(argc != 3){
		cprintf("Usage: shmap <start> <end>\n");
		return 0;
	}
	uint32_t start = hex2int(argv[1]);
	uint32_t end = hex2int(argv[2]);

	pte_t * pte;
	uintptr_t index = ROUNDUP(start, PGSIZE);
	physaddr_t mapped_addr;
	while(index <= end){
		pte = pgdir_walk(kern_pgdir, (void*) index, 0);
		if(pte == NULL || !(*pte & PTE_P)){
			cprintf("%08x   =>   not mapped\n", index);
		}else{
			if(*pte & PTE_PS){	// large page
				index -= PGSIZE;
				index += PTSIZE;
			}
			mapped_addr = PTE_ADDR(*pte);
			cprintf("%08x  =>  %08x  ", index, mapped_addr);
			// print permission bits
			if (*pte & PTE_W) {
                cprintf(" W");
            }
			if (*pte & PTE_U) {
                cprintf(" U");
            }
			if (*pte & PTE_PWT) {
                cprintf(" PWT");
            }
			if (*pte & PTE_PCD) {
                cprintf(" PCD");
            }
			if (*pte & PTE_A) {
                cprintf(" A");
            }			
			if (*pte & PTE_D) {
                cprintf(" D");
            }                        
			if (*pte & PTE_PS) {
                cprintf(" PS");
            }						
			if (*pte & PTE_G) {
                cprintf(" G");
            }
			cprintf("\n");
		}

		index += PGSIZE;
	}
	return 0;
}

int 
mon_chmap(int argc, char**argv, struct Trapframe *tf){
	if(argc != 3){
		cprintf("Usage: chmap <+/-permission> <addr>\n");
		return 0;
	}
	// mode
	int mode;
	if(argv[1][0] == '+'){
		mode = 1;
	}else if(argv[1][0] == '-'){
		mode = 0;
	}else{
		cprintf("Usage: chmap <+/- permission> <addr>\n");
		return 0;
	}

	// permission
	char * perm_s = &argv[1][1];
	int perm = 0;
    if (strcmp(perm_s, "W") == 0){
        perm = PTE_W;
	}else if(strcmp(perm_s, "U") == 0){
        perm = PTE_U;
	}else if(strcmp(perm_s, "PWT") == 0){
        perm = PTE_PWT;
    }else if(strcmp(perm_s, "PCD") == 0){
        perm = PTE_PCD;
    }else if(strcmp(perm_s, "A") == 0){
        perm = PTE_A;
    }else if(strcmp(perm_s, "D") == 0){
        perm = PTE_D;
    }else if(strcmp(perm_s, "G") == 0){
        perm = PTE_G;
    }else{
        cprintf("Usage: <option> <addr>\n");
        return 0;
    }

	// address
	uintptr_t addr = hex2int(argv[2]);

	pte_t * pte = pgdir_walk(kern_pgdir, (void*)addr, 0);
	if(pte){
		if(mode){	// add permission
			*pte = *pte | perm;
		}else{	// remove permission
			*pte = *pte & (~perm);
		}
	}
	return 0;
}

int
mon_memdump(int argc, char**argv, struct Trapframe *tf){
    uint32_t i, start, end;
	int kind;
    if (argc != 4) {
        cprintf("Usage: memdump <-v|-p> <begin> <end>\n");
        return 0;
    }
    if (strcmp(argv[1], "-v") == 0) {
        kind = 0;
    }
    else if (strcmp(argv[1], "-p") == 0) {
        kind = 1;
    }
	else {
        cprintf("Usage: memdump <-v|-p> <begin> <end>\n");
        return 0;
    }
    
	start = hex2int(argv[2]);
    end = hex2int(argv[3]);

    cprintf("0x%x :", start);
    int cnt = 0;
    for (i = start; i <= end; ++i) {
        if (cnt == 8) {
        	cnt = 0;
        	cprintf("\n0x%x: ", i);
        }
        if (kind) {
            cprintf(" %02x", ((uint32_t)*(char *)(i + KERNBASE)) & 0xff);
        }
        else {
            cprintf(" %02x", ((uint32_t)*(char *)i) & 0xff);
        }
        	cnt++;
    }
    cprintf("\n");
    return 0;
}

int
mon_c(int argc, char **argv, struct Trapframe *tf){
	// if the monitor return, the program will continue
	if(tf == NULL){
		cprintf("not in debug mode\n");
		return 0;
	}
	tf->tf_eflags &= ~FL_TF;	// clear tf bit in EFLAG
	return -1;	// quit monitor loop
}

int
mon_si(int argc, char **argv, struct Trapframe *tf){
	if(tf == NULL){
		cprintf("not in debug mode\n");
		return 0;
	}
	tf->tf_eflags |= FL_TF;	// set tf bit in EFLAG
	cprintf("tf_eip=%08x\n", tf->tf_eip);
	struct Eipdebuginfo e;
	if(debuginfo_eip(tf->tf_eip, &e) == 0){	// success find debug info
		char func_name[e.eip_fn_namelen + 1];	// str end with '\0'
		int i;
		for(i = 0; i < e.eip_fn_namelen; i++){
			func_name[i] = e.eip_fn_name[i];
		}
		func_name[e.eip_fn_namelen] = '\0';
		cprintf("%s:%d: %s+%d\n", e.eip_file, e.eip_line, func_name, tf->tf_eip - e.eip_fn_addr);
	}
	return -1;
}

int
mon_x(int argc, char **argv, struct Trapframe *tf){
	if(argc != 2){
		cprintf("Usage: x <address>\n");
		return 0;
	}
	uint32_t address = hex2int(argv[1]);
	cprintf("%d\n", (*(uint32_t *)address));
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

	if (tf != NULL)
		print_trapframe(tf);

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
