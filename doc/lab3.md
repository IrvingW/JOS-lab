# Lab3 User Environments
[TOC]
## 前言
> 这次的实验相比较上两次的实验，难度有所加大．在完成的过程中，我查看了大量的文档以及网上的实验攻略等．
> 在次要感谢这些文档和攻略的作者．
> 本文档将主要就整个实验过程进行记录，并且就笔者遇到的一些问题，进行了较详尽的探究．对于一些由该部分
> 话题笔者联想引申出来的内容，笔者也进行了记录

## 实验过程
### Exericise 1.
只需要修改`kern/pmap.c`中的`mem_init`函数，照抄pages结构的分配和
任务可以细分为两部分:
1. 在虚拟地址空间建立起来之前，用`boot_alloc`静态分配一段内存给envs
2. 在建立虚拟地址空间的时候，将UENV映射到这一段分配好的内存上，并且权限和pages一样(PTE_U)，允许用户进行读操作．
此时让我们重新编译运行JOS,我们可以从控制台的输出中看到`check_kern_pgdir()`函数成功通过，说明我们的修改成功了．


### Exercise 2.
在`kern/init.c`中可以看到新添加了几行用于初始化运行环境和trap等，如下所示：
```c
	// Lab 3 user environment initialization functions
	env_init();
	trap_init();

  #if defined(TEST)
	// Don't touch -- used by grading script!
	ENV_CREATE(TEST, ENV_TYPE_USER);
  #else
	// Touch all you want.
	ENV_CREATE(user_buggyhello, ENV_TYPE_USER);
  #endif // TEST*

	// We only have one user environment for now, so just run it.
	env_run(&envs[0]);
```
在这之后我们有了第一个也是唯一一个环境，所以在末尾处，用evn_run将这个环境调度了起来．

* env_setup_vm
在UTOP以上的虚拟内存空间是每一个环境都相同的，除去UVPT的部分是每一个运行环境都不相同以外，其余部分都是一样的(JOS中，并不是每一个进程拥有自己的内核栈，而是所有的进程共享同一个内核栈),其中pages结构保存的是物理页的信息，每一个进程都是一样的.此时此刻，我们只需要建立一个简单的页表结构，只需要映射UTOP以上的空间即可，UTOP以下的空间暂时先空着就可以了．
需要注意的是env_pgdir所在的页的pp_ref需要增加，这样一来env_free才能够正常的工作，当一个环境被抹杀掉的时候，他所占用的用来存储页表结构的物理页才能够被自动释放．

* region_alloc
申请len字节的物理地址地址空间,并把它映射到虚拟地址va上,不要 初始化为0或其它操作,页需要能被用户写,如果任何步骤出错panic,注释提示注意页对齐.
回想之前的lab2,我们实际有做过类似的工作．
对起始地址ROUNDDOWN,结束的地址ROUNDUP,在起始到结束地址当中的每一个页，调用page_insert插入一个页．
需要注意pp_ref理论上将需要增加，但是在page insert中会自动增加这个值，所以不需要在代码中增加了．


* load_icode
这个函数为一个用户进程加载二进制程序，初始化栈结构以及进程的一些寄存器．
只在kernel 初始化的时候被调用，当第一个用户级的进程跑起来之后就不再用这个函数了．
从ＥＬＦ可执行文件中将各个段按照ELF Programmer Header中指定的虚拟地址加载到内存中．
比较特殊的是BSS等实际在ELF可执行文件中不存在的段，也需要在虚拟地址空间中分配一段内存，并且需要初始化该区域为０．

最后的最后，为程序的栈分配一个页
关于如何读取ELF可执行文件的部分可以参照boot/main里面的这一段代码，基本上非常的相像．
```c
void
bootmain(void)
{
	struct Proghdr *ph, *eph;

	// read 1st page off disk
	readseg((uint32_t) ELFHDR, SECTSIZE*8, 0);

	// is this a valid ELF?
	if (ELFHDR->e_magic != ELF_MAGIC)
		goto bad;

	// load each program segment (ignores ph flags)
	ph = (struct Proghdr *) ((uint8_t *) ELFHDR + ELFHDR->e_phoff);
	eph = ph + ELFHDR->e_phnum;
	for (; ph < eph; ph++)
		// p_pa is the load address of this segment (as well
		// as the physical address)
		readseg(ph->p_pa, ph->p_memsz, ph->p_offset);

	// call the entry point from the ELF header
	// note: does not return!
	((void (*)(void)) (ELFHDR->e_entry))();

bad:
	outw(0x8A00, 0x8A00);
	outw(0x8A00, 0x8E00);
	while (1)
		/* do nothing */;
}
```

* env_run()
这里我们要明确一个概念，在JOS中，内核kernel拥有一个自己的运行环境，并且所有进程都恭喜这一个内核进程环境，而不是像XV6一样每一个进程都有自己的内核栈，相当于有多个内核环境．
接下来我们会看到所有的exception处理函数都运行在内核环境中．


### Exercise 3.
这部分要求我们阅读文档熟悉Intel 80386机器的中断机制，关于这部分的一些体会我会在下一节中详细介绍．


### Exercise 4
先看宏TRAPHANDLER(name, num)注释说你需要在c中定义一个类似void NAME();然后把NAME作为参数传给这个函数,num为错误号,TRAPHANDLER_NOEC 是NO ERROR CODE的版本 :-) 多pushl了一个$0,注释说保持结构一样,对照上方的 图,可以看到没有push的会少一个push,这两个宏实际是函数模板,这里我们用这两个宏来实现trapentry.S的handlerX的部分．

* _alltraps
```c
_alltraps:
  pushw $0
  pushw %ds
  pushw $0
  pushw %es
  pushal
  movw $GD_KD,%ds
  movw $GD_KD,%es
  pushl %esp
  call trap
```
这一段是使用汇编写成的，我们可以去看一下`trap`这个函数的参数，发现是一个trapframe,所以在调用trap之前需要将一个trapframe压到栈上，然后将％esp作为指向这个结构的头部的指针，同时也就是trap所需要的参数，压入栈中，就可以调用trap函数了．

接下来 开始实现trap函数trap_init，要用宏SETGATE(gate, istrap, sel, off, dpl)在inc/mmu.h中配置IDT表的结构，要注意的是这里根据文档我们知道　INTO, INT3, BOUND, INT n　是允许软件中断的，也就是说，他们的DPL需要设置为３．
例子
```c
SETGATE(idt[T_DIVIDE ],0,GD_KT,ENTRY_DIVIDE ,0);
```
到这里为止，如果用户程序发生了除零中断，大致的流程如下所示
> 发生除零中断　＝＞　硬件根据trap_init()中配置的IDT表找到所需要的处理函数入口　＝＞　在处理函数中跳到_alltraps处　＝＞　_alltrap 在栈中压入Trapframe结构体，调用trap函数　＝＞　进入trap dispatch中进行分发以及处理

* pusha 与　pushal的区别
我们可以参照这张表
> pusha	: Push AX, CX, DX, BX, original SP, BP, SI, and DI
> pushal: Push EAX, ECX, EDX, EBX, original ESP, EBP, ESI, and EDI


### Exercise 5
在dispatch函数中根据trap_no进行分发，这里我们具体考虑的一个exception是page fault．
通过对trap_number的判定，将page fault交给`page_fault_handler(tf)`来处理，值得注意的是这个函数是无返回的，他会销毁当前正在运行的用户程序环境．
实现比较简单这里不费话了．

### Exercise 6
预期实现目标是使用sysenter 和 sysexit 指令实现系统调用，sysenter/sysexit 指令设计得比int/iret快. 它们用寄存器而不是用栈．
需要在`kern/trap.c`中添加设置必要的MSR的代码，
在文档中给出了一个参照代码链接，在该文件中有三段代码是我们可以参考的：
```c
wrmsr(0x174, __KERNEL_CS, 0);		/* SYSENTER_CS_MSR */
wrmsr(0x175, page+PAGE_SIZE, 0);	/* SYSENTER_ESP_MSR */
wrmsr(0x176, page, 0);			/* SYSENTER_EIP_MSR */
```
其实在后面的注释中就已经
在文档所给出的另一个链接中，我们可以找到使用MSR的使用的一些要求如下
> These must be accessed through rdmsr and wrmsr
IA32_SYSENTER_CS (0x174)
IA32_SYSENTER_ESP (0x175) - The kernel's ESP for SYSENTER.
IA32_SYSENTER_EIP (0x176) - The kernel's EIP for SYSENTER. 

根据以上我们了解的情况，我们在trap.c中添加如下代码用来设置MSR	
```c
// set MSR
extern void sysenter_handler();
wrmsr(0x174, GD_KT, 0);		/* SYSENTER_CS_MSR */
wrmsr(0x175, KSTACKTOP, 0);	/* SYSENTER_ESP_MSR */
wrmsr(0x176, sysenter_handler, 0);			/* SYSENTER_EIP_MSR */
```

* 在实现syscall函数的时候需要知道
GCC's 内联汇编不支持直接把值放入ebp，所以你可以用push+pop来放入ebp (以及esi和其它寄存器). 
返回地址放入esi可以用类似如下指令leal after_sysenter_label, %%esi

这里执行编译却发现找不到`wrmsr`的定义，经过一番寻找，终于是在MIT同一门课程的网站上找到了解决的方法
将下面一段代码添加到`inc/x86.h`文件中就可以了
```c
#define wrmsr(msr,val1,val2) \
  __asm__ __volatile__("wrmsr" \
  : /* no outputs */ \
  : "c" (msr), "a" (val1), "d" (val2))
```

* 完成这一切之后syscall 调用的流程：
我们就用一个比较经典的`cprintf`函数调用来说明
cprintf调用的底层肯定是要调用系统调用来将字符输出到屏幕上，在我们的JOS中最后底层的系统调用是这样写的:
```c
void
sys_cputs(const char *s, size_t len)
{
	syscall(SYS_cputs, 0, (uint32_t)s, len, 0, 0, 0);
}
```
可以看到使用了一个syscall的函数，这里需要留意，在JOS中总共有两个`syscall`函数，一个就是lib目录下的syscall.c文件中的，同时也正是上面这几行代码中所调用的那个函数．
这个函数中使用`sysenter`命令实现系统调用，调动了处于kern/syscall.c中的另一个`syscall`函数，这个函数相当于一个dispatch的节点，根据系统调用号调用不同的系统中的实现函数．


### Exercise 8
在实现sbrk()方法之前，有两件前提条件需要达成：
1. 我们要在Env结构中添加一个字段，用来记录env_break
2. 相应的需要在env.c中的load_icode函数中加载ELF可执行文件的时候要添加初始化env_break的代码．
只需要申请多个页并把它们插入到页表的正确的位置, 之前修改的Env的结构来记录当前程序的断点，并根据sbrk()来更新

### Exercise 9
首先修改trap_dispatch(trap.c)
在monitor.c的`monitor`函数中我们观察到
```c
if (runcmd(buf, tf) < 0) break;
```
这句也就是说如果一个命令的执行函数返回小于零的值，monitor()就会退出，这样一来就可以回到之trap_dipather进入的地方继续执行了．于是我们可以利用这一点来实现退出阻塞在控制台的状态，继续执行代码．
可以用到这个技巧的有两个功能：
1. 单步执行功能
2. 继续执行功能
当然，这两个功能在具体实现上都还有一定的差异．
这两个函数都使用了EFLGS寄存器上的同一个bit位－－TF(trap flag)，这个位如果被写成１的话，CPU执行每条指令都会触发一个DEBUG exception．这一点恰好可以为我们实现单步执行的功能所用．在返回一个小于零的值导致monitor()函数退出之前，写上tf bit，这样一来接下来的每一条指令就都会通过debug exception将控制流导入monitor的循环之中．
除了我们已经非常熟悉的在monitor模块中新增加三条命令以外，我们还得在trap_dispatch中加入新的DEBUG exception 以及　breakpoint exception 的处理逻辑
```c
case T_BRKPT:
	cprintf("trap T_BRKPT\n");
	monitor(tf);
	return;
case T_DEBUG:	// if tf bit of EFLAG is set, CPU will issue T_DEBUG exception
  cprintf("trap T_DEBUG\n");
  monitor(tf);
```

### Exercise 10
这个练习比较简单，直接贴主要代码．另外提醒大家一个一开始我没有注意到后来稍微debug了一会儿的点
如果va 传入是1，len 传入也是1，这时不能va先ROUNDOWN作为起始地址，因为涉及到检查失败时设置user_mem_check_addr，像这种输入user_mem_check_addr就会被设置成0x0,而不是0x1
```c
int
user_mem_check(struct Env *env, const void *va, size_t len, int perm)
{
  uintptr_t va_start = (uintptr_t) va;
  uintptr_t va_end   = (uintptr_t) va + len ;
  uintptr_t va_iterator;
  perm |= PTE_P;
  for (va_iterator = va_start; va_iterator < va_end; va_iterator = ROUNDDOWN(va_iteratoridx+PGSIZE, PGSIZE)) {
    if (va_iterator >= ULIM) {
      user_mem_check_addr = va_iterator;
      return -E_FAULT;
    }
    pte_t * pte = pgdir_walk (env->env_pgdir, (void*)va_iterator, 0);
    if ( pte == NULL || (*pte & perm) != perm) {
      user_mem_check_addr = va_iterator;
      return -E_FAULT;
    }
  }
  return 0;
}
```
### Exercise 12
首先观察整个文件，在umain中调用了两次evil，而在evil中第一句是一句如果是用户级别的话会导致异常的访问kernel内存区域的语句．如果成功实现了的话，应该是第一次通过call gate以kernel级运行evil,会正常打出＂RING 0!＂，而第二次调用的结果是遇到evil的第一句触发一个异常，后面的字符串不会被打出来．

考虑实现步骤

1. sgdt 来知道gdt的地址
2. 知道了地址，用sys_map_kernel_page来吧gdt映射到用户可编辑!?
3. 用SETCALLGATE和前面设置IDT类似的来设置GDT(位置i) 指向我们新设计一个函数F入口
4. 内联汇编根据F的参数压栈
5. lcall 位置i
6. F(){执行evil 并 lret}
7. 恢复 覆盖掉的GDT

lret默认有讲特权级降级到原来的级别的功能，所以千万不要忘记使用这个命令，否则将会两次都打出字符串．

实现代码如下：
```c
char user_gdt[PGSIZE*2];
struct Segdesc *gdte_ptr,gdte_backup;
static void (*ring0_call_func)(void) = NULL;
static void
call_fun_wrapper()
{
    ring0_call_func();
    *gdte_ptr = gdte_backup;
    asm volatile("leave");
    asm volatile("lret");
}
```

```c
// Invoke a given function pointer with ring0 privilege, then return to ring3
void ring0_call(void (*fun_ptr)(void)) {
    // 1.
    struct Pseudodesc gdtd;
    sgdt(&gdtd);
    // 2.
    int r;
    if((r = sys_map_kernel_page((void* )gdtd.pd_base, (void* )user_gdt)) < 0){
      cprintf("ring0_call: sys_map_kernel_page failed, %e\n", r);
      return ;
    }
    ring0_call_func = fun_ptr;// DONT MOVE THIS BEFORE SYS_MAP_KERNEL_PAGE
    // 3.
    struct Segdesc *gdt = (struct Segdesc*)((uint32_t)(PGNUM(user_gdt) << PTXSHIFT) + PGOFF(gdtd.pd_base));
    //cprintf("(user_gdt,gdt) = (%08x,%08x)\n", (uint32_t)user_gdt,(uint32_t)gdt);
    int GD_EVIL = GD_UD; // 0x8 * n  0x18(GD_UT) 0x20(GD_UD) 0x28(GD_TSS0)
    gdte_backup = *(gdte_ptr = &gdt[GD_EVIL >> 3]);
    SETCALLGATE(*((struct Gatedesc *)gdte_ptr), GD_KT, call_fun_wrapper, 3);
    // 4. 5. 6. 7.
    asm volatile ("lcall %0, $0" : : "i"(GD_EVIL));
```

## 延伸
### 用户态程序的加载和执行
这是较为简单的一部分，Lab 3中已经为我们准备好了大部分代码，为了运行起一个用户态程序我们只需为其设置页表、加载可执行文件到内存，最后利用iret指令返回用户态即可。具体而言，由于我们现在并没有文件系统，我们的用户态程序是通过binary的方式链接到kernel的镜像文件上的，这些程序都位于kernel文件的.data节，我们可以通过Lab 3中已经为我们写好的宏来选择一个用户态程序进行加载。Lab 3中提供的宏最终调用了env_create函数，在这个函数中我们调用load_icode函数，将用户程序的内容加载到内存中并设置好这些内容对应的页表，该过程类似于加载kernel镜像的过程，不再详述。加载完毕后，调用env_run函数即可运行该用户态程序。这是通过iret指令实现的，也就是说，尽管没有对应的异常，我们仍可以使用iret指令，只要将栈安排成和通过Interrupt Gate或Trap Gate进入的时候产生的栈一样即可，这是通过struct Trapframe实现的。这个结构体按照产生异常时栈的布局，设置了其成员的类型及顺序，而每个用于表示用户态进程的struct Env中都包含一个struct Trapframe作为成员。这样，只要在初始化的时候（env_init和env_alloc中）设置好相应的初始值，并在加载ELF文件时设置好其入口点，就可以顺利通过几条pop指令和一条iret指令顺利运行一个用户态程序。

###系统调用的实现
尽管经过以上步骤，一个用户态程序已经可以运行，但其甚至连hello world也无法实现，因为输入输出必须经过内核操作相应的硬件才能实现，因此在用户态势必通过系统调用才能实现。实现系统调用有两种方式，一是采用int $SYSCALL_NUM的形式，选择一个中断号供系统调用使用，另一种是使用专门用于系统调用的指令，如sysenter、sysexit指令，本次Lab规定必须使用sysenter、sysexit指令实现。这两条指令需要操作MSR进行初始化，所谓MSR即Model Specific Register，在不同型号的CPU上可能不同，这次需要设置的是0x174-0x176（MSR寄存器有很多，形成了自己的地址空间）三个寄存器。根据最新的Intel文档，0x175号寄存器用于存放EIP，0x176号寄存器用于存放ESP，而Lab中提供的阅读材料（Linus Torvalds在2002年为Linux打的补丁）显示0x175号用于存放ESP而0x176号用于存放EIP。到底何者正确呢，事实上两者都正确，因为MSR本来就是为了不兼容而诞生的，是Model Specific的，相隔十来年其定义发生了变化也属正常。经过测试，可能由于在我们的Lab中使用的是极早期的QEMU版本，后者的顺序才是正确的，但这并不能代表在其他模拟器或真实的机器上一定也是这样定义的。
 通过在kern/trap.c中添加了三条wrmsr指令初始化后，sysenter、sysexit指令即可使用了。我们的用户态程序进行系统调用后，最后都会来到lib/syscall.c中的syscall函数，我们需要在此处写内联汇编调用sysenter指令。注意sysenter指令并不会保存调用者的eip和esp，因此需要手动保存，占用两个寄存器，此外我们还要支持一个系统调用号及五个参数，需要占用6个寄存器进行传参，这样一来寄存器就不够用了（因esp会由于sysenter指令而被覆盖）。为了解决这个问题，我的解决方案是只采用一个寄存器保存返回地址和调用者的esp，方法是使用这一个寄存器（我采用的是ebp）保存调用者的esp，并且在调用者的栈上压入其返回地址，这样可以通过保存在ebp
中的esp间接地获取返回地址，由此即可顺利返回。执行sysenter指令后就来到了kern/trapentry.S中的sysenter_handler（该入口点在此前初始化时指定），它将通过寄存器传来的参数压栈，并设置es、ds，然后就调用syscall函数（位于kern/syscall.c），执行具体的system call。待函数返回后，由于函
数调用规约，ebp的值并未受到影响，我们可以恢复es、ds，并从ebp中获得返回地址和要切换到的esp，载入到对应的寄存器（edx和ecx），最后通过一条sysexit指令即可返回用户态。
只要小心地编写汇编和内联汇编，保证以上部分正常工作，系统调用就算是完成了，剩下的工作不涉及用户态和内核态的切换，可以使用C编写，我们只需要关心具体的业务逻辑即可。至此，hello程序已经可以输出hello world了，但仍会在第二次cprintf调用时出错，因为thisenv变量没有设置（这也是Exercise 2完成后运行hello会出错的原因，而不是Lab介绍中写的因为调用了系统调用而出错，因为此时syscall函数中甚至还没有写上sysenter指令），解决方法是在lib/libmain.c中加上一句初始化语句即可（这句语句也需要调用系统调用）。
 需要我们实现的的系统调用只有sys_cputs和sys_sbrk，其他均已经为我们实现。
 sys_cputs函数默认已经包含一句cprintf，因此已经可以正常工作，此前hello程序已经能正常输出helloworld。然而，作为一个系统调用，除了实现用户程序要求的功能，还必须采取不信任用户程序的态度，检查其提供的输入，防止有bug的或恶意的用户程序对内核造成破坏。因此，我们需要回到Lab 2中的kern/pmap.c中，添加一个user_mem_check函数，检查用户是否有权限使用它提供的地址（可能内核具有权限使用该地址，但用户没有）。在sys_cputs中我们利用这个新添加的函数，检查用户的输入是否合法，如果不合法则销毁用户进程，避免其破坏内核的一致性。
  sys_sbrk函数可以扩展用户进程的data段，为其提供一种分配内存的基本机制，使用Lab 2中提供的接口即可实现。有了这个函数，我们就可以说用户程序已经具备了堆，这样我们的用户程序已经和通常意义上的用户程序较为接近了，除了不具备动态链接库。事实上，在POSIX兼容的系统上的确有sbrk系统调用，在UNIX和Linux上malloc库的早期实现确实是使用的sbrk系统调用，后来则采用了mmap系统调用作为获取内存的方式，有些库提供了选项可以在两种底层实现中选择一种进行编译。


### 中断（异常）处理的实现
对于中断的处理，需要在kern/trap.c中的trap_init函数中通过SETGATE宏设置IDT表项。尽管原则上这个Lab中处理的属于“Trap”，应该使用Trap Gate，但我使用了Interrupt Gate，这是因为本次Lab中提供的中断处理函数trap要检查中断是否已经关闭（即eflags的IF位为零），为了适应这一点，不能使用Trap Gate。具体的Trap Gate对应的入口点在kern/trapentry.S中定义，它们在压入error code（如果其本身没有error code）和trap number后都会跳转到_alltrap，在此处保存用户的段寄存器和通用寄存器，形成和Trapframe定义一致的栈布局，然后调用trap函数，该函数的参数即为struct Trapframe *tf。
 在本次Lab中，需要进行处理的仅有Debug Exception、Breakpoint Exception和Page Fault，对于其他异常均使用默认的应对措施，即若引发异常者为用户，销毁该用户进程，若为内核则产生一个panic。对于Page Fault异常，由专门的函数page_fault_handler处理，不过本次Lab并未提出相关的处理要求，因此对于用户的page fault实际上我们总是销毁该进程而不是试图去处理它。对于Breakpoint异常，这是本Lab中唯一需要将其Interrupt Gate的DPL设置为3的异常，事实上根据Intel的文档来看除了Breakpoint异常允许用户通过INT3指令产生，就只有Overflow异常允许用户通过INTO指令产生，其他任何异常都不应该由用户通过int $trapno的形式产生并调用。用户通过该异常可以进入kernel monitor，我们为其增添了三条命令，分别是c、si和x，即继续执行、单步执行和显示内存。其中c和x都很简单，c命令直接从handler中返回即可，x命令需要parse一下输入，获取用户输入的地址，并检查该地址用户进程是否可以读取。对于单步执行，要分两部分实现，当用户输入si命令时，调用第一部分，将Trapframe中eflags的TF位置为1，然后立即返回用户态。由于此时用户的elfags中TF为1，它只会执行一条指令，接着引发一个Debug Excpetion，此时由第二部分处理该异常，输出当前的eip并通过debuginfo_eip函数获取其在用户程序源码中的位置（注意此时是从用户程序的stabs中获取的调试信息，要先用user_mem_check检查其合法性），最后进入和monitor相同的循环中读取用户命令（不能直接调用monitor函数以免重复输出欢迎信息）。
 

## 总结
至此，本次Lab中所有Exercise涉及实现的内容均已介绍完毕，本文档到此结束，但目前还无法处理外部中断，也不支持多进程运行和调度，更多后续内容留待接下来Lab的文档继续介绍。