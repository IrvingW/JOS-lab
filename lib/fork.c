// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at vpt
	//   (see <inc/memlayout.h>).

	// LAB 4: Your code here.
	if(!((err & FEC_WR) && (vpd[PDX(addr)] & PTE_P) &&  (vpt[PGNUM(addr)] & (PTE_P | PTE_COW)) == (PTE_P | PTE_COW)))
		panic("pgfault: real page fault\n");

	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.
	//   No need to explicitly delete the old page's mapping.

	// LAB 4: Your code here.
	if((r = sys_page_alloc((envid_t) 0, (void *)PFTEMP, PTE_P|PTE_U|PTE_W)) < 0){
		panic("sys_page_alloc: %e\n", r);
	}
	addr = ROUNDDOWN(addr, PGSIZE);
	memmove((void *)PFTEMP, addr, PGSIZE);
	if((r = sys_page_map((envid_t)0, (void *)PFTEMP, (envid_t)0, addr, PTE_U|PTE_P|PTE_W)) < 0){
		panic("sys_page_map: %e\n", r);
	}
	if((r = sys_page_unmap((envid_t)0, (void *)PFTEMP)) < 0){
		panic("sys_page_unmap: %e\n", r);
	}

}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
	int r;

	// LAB 4: Your code here.
	void * addr = (void *)(pn * PGSIZE);
	int perm1 = PTE_U | PTE_P | PTE_COW;
	int perm2 = PTE_U | PTE_P;
	if(vpt[pn] & (PTE_W | PTE_COW)){
		if((r = sys_page_map((envid_t)0, addr, envid, addr, perm1) < 0))
    		panic("sys_page_map: %e\n", r);
		if((r = sys_page_map((envid_t)0, addr, 0, addr, perm1) < 0))	// chage self page to copy on write
    		panic("sys_page_map: %e\n", r);
	}else{
		if((r = sys_page_map((envid_t)0, addr, envid, addr, perm2) < 0))
    		panic("sys_page_map: %e\n", r);
	}
	return 0;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use vpd, vpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
	// LAB 4: Your code here.
	set_pgfault_handler(pgfault);
	extern void _pgfault_upcall(void);
	int r;
	uintptr_t addr;
	envid_t child_id = sys_exofork();
	if(child_id < 0)
		panic("sys_exofork: %e", child_id);
	if(child_id == 0){
		// child
		thisenv = &envs[ENVX(sys_getenvid())];
		return 0;
	}
	// parent
    for (addr = UTEXT; addr < USTACKTOP; addr += PGSIZE)
     	if ((vpd[PDX(addr)] & PTE_P) && (vpt[PGNUM(addr)] & (PTE_P | PTE_U)) == (PTE_P | PTE_U))
			duppage(child_id, PGNUM(addr));

	if((r = sys_page_alloc(child_id, (void *)(UXSTACKTOP - PGSIZE), PTE_W|PTE_U|PTE_P)) < 0){
		panic("sys_page_alloc: %e\n", r);
	}
	if((r = sys_env_set_pgfault_upcall(child_id, _pgfault_upcall)) < 0){
		panic("sys_env_set_pgfault_upcall: %e\n", r);
	}

	// Start the child environment running
	if ((r = sys_env_set_status(child_id, ENV_RUNNABLE)) < 0)
		panic("sys_env_set_status: %e", r);

	return child_id;
}

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
