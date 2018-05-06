## JOS-Lab 4: Preemptive Multitasking
[TOC]

>本次实验将会实现抢占式的多任务调度．
PartA部分将首先为JOS添加支持多处理器的支持代码，并且实现一种简单的Round Robin的调度模式，还会添加与创建或者销毁环境，映射内存等有关的一些系统调用．
PartB部分需要实现一个fork()函数，这个应该比较熟悉，和Unix系统上的fork()函数的作用是一样的，以一个用户进程环境为模板创建一个新的拷贝进程环境．
PartC，我们将会加入进程间通信的功能．还有硬件时钟中断和抢占调度．


### Part A: Multiprocessor Support and Cooperative Multitasking
#### Multiprocessor Support 
JOS将要实现的是一种名为SMP(symmetric multiprocessing)的多处理器模型，所有的CPU对于系统资源都拥有相同获取权利．但是他们各自的职能却分为两种：BSP和AP
哪一个CPU属于哪种使用硬件和BIOS来决定的
* BSP: (bootstrap processor)用于执行初始化操作系统的代码，我们至今为止写的代码都属于这个CPU需要执行的．
* AP: (application processors)当操作系统被启动起来之后需要被BSP激活的CPUs
每一颗CPU都有自己的LAPIC(local APIC)单元，之前学过APIC,是用来递送中断的模块，而多核系统中，每一个CPU都有一个自己的APIC模块．CPU通过MMIO来和自己的LAPIC进行通信，直接对物理地址上一些直接和某些寄存器相连的位置进行读写就可以实现通信．LAPIC所在的物理地址处于`0xFE000000`，这个地址超出了我们之前用的最低4MB物理空间，所以不能再使用KERNELBASE的方法直接映射了．这个lab里，我们会将虚拟地址空间最顶端的32MB（从0xFE000000开始），映射到包含LAPIC的 IO hole上去.其实通过这个映射虚拟地址和物理地址就是相同的．

#### Application Processor Bootstrap
APs在启动之前，BSP必须先收集有关多处理器系统的信息，比如CPU的数量，他们的APIC id以及LAPIC MMIO的地址等．这些信息存储在BIOS区域的MP configuration table内．
APs一开始的时候当然是运行在实模式下的，所以AP启动的代码需要被拷贝到实模式下可以寻址的位置，这里我们定义了一个位置`MPENTRY_PADDR`(0x7000)
在这之后，BSP会一个一个的唤醒AP,通过发送STARTUP的信号给每个AP的LAPIC的方式．同时被发送的还有最开始AP需要执行的代码的地址．BSP在一个AP的状态变成已经启动（CPU_STARTED）之后才会继续去唤醒别的AP.

##### Exercise 1
```c
if ((i > 0 && i < npages_basemem) || i >= cur_free)
```

```c
if ((i > 0 && i < npages_basemem && i != PGNUM(MPENTRY_PADDR)) || i >= cur_free)
```

#### Per-CPU State and Initialization
多处理器操作系统与单核的一个很大的不同是，有一些状态是每个处理器自己才能看到的，而有的状态是全局的，也就是说是所有CPU共享的．
下面的这些状态是每个CPU各有一份的：
* kernel stack
percpu_kstacks[NCPU][KSTKSIZE]这个数组结构为每一个CPU的栈结构预留了空间．还记得在Lab2的时候，我们将BSP的栈映射到了KSACKTOP的位置，这一次我们还会为每一个AP的栈建立映射．注意在每一个内核栈之间会有一段KSTKGAP大小的invalid memory．
* TSS and TSS descriptor
上一次实验中在trap.c中定义的ts这个变量（用来记录BSP的taskstate),由于我们进入了多核的时代就作废了，每一个CPU都有一个用来taskstate结构．同时原来的trap_init_percpu函数看来这次也要修改了．
* current environment
由于每个CPU都可以同时运行不同的用户进程，原来的全局current env 看来也不能用了，重新定义的变量在struct CPU结构中的cpu_env字段，指向该CPU当前正在运行的环境．
* system register
* idle environment
每一个CPU上会有一个默认的运行环境，虽然这个进程里不做什么事情，但是同一个环境只能同时运行在一个CPU上，所以还是要定义多个默认环境．默认情况下，envs[cpunum()]是一个CPU的默认运行环境．

##### Exercise 2.
这个和之前为BSP设置内核栈的过程差不多，唯一不同的是原来将其余的所有页都设置成为了guard page，而这一次只需要设置KSTKGAP大小的几个页为guard pages就可以了．
这里还有一个bug,就是原来坑爹的lab2吧好象是，把虚拟地址最上面那一段改成大页映射的了，这里我偷了个懒，把原来开启大页映射的那一句改掉了，改成小页映射的．

##### Exercise 3.
需要修改原来lab3中实现的trap_init_percpu()函数，原来只是为一个核准备的．两者主要的不同在于原来使用全局变量ts的地方全部应该使用this_cpu->cpu_ts来代替，而原来直接使用BSP内核栈的地方(KSTACKTOP),需要替换成该CPU自己的内核栈．

#### Locking
##### Exercise 4
这里我们引入一把全局的kernel锁，以防止多个CPU由于都运行内核代码而产生竞争．在这种模型下，用户态的环境可以运行在任何一个CPU上面，而任何一个环境想要进入内核态都必须取得这把全局的锁，否则就只好等待．
文档中指引我们在四个地方加上锁(通过lock_kernel()和unlock_kernel()方法)
1. i386_init()
2. mp_main()
3. trap()
4. env_run()
前面三个都比较简单，而且代码中其实有注释提示加在哪里，只有最后一个，需要知道env_pop_tf()函数中会执行一句`iret`，这句之后就正式退出了内核态．所以unlock就得在这个函数之前调用．
除了上面４个地方，其实还有一个地方需要加锁，因为syscall走的不是IDT，所以在syscall.c中还要单独加锁．

##### Exercise 4.1
这个练习我们来实现ticket lock，这种锁上学期CSE已经讲过了，和银行的排号系统比较类似，他的特点是不会有人被饿死，而且是一种公平锁.
锁里有两个值，当前排到的号码，下一个被取的号码，感觉是不是和银行叫号很像啊．
取消USE_TICKET_SPIN_LOCK的注释后，有四个地方需要实现：
* holding() 里的 用于判断当前CPU是否持有该锁return lock->own != lock->next && lock->cpu == thiscpu;
* __spin_initlock() 里的 用初始化锁lk->own = lk->next = 0;
* spin_lock() 里的 用于申请锁
```c
unsigned thisticket = atomic_return_and_add(&(lk->next), 1);
while ( thisticket != lk->own )
	asm volatile ("pause");
```
* spin_unlock()里的 用于释放锁atomic_return_and_add(&(lk->own), 1);
运行了一下竟然卡死了，呵，最后看叶神的文档得知是lk->own竟然不能保证原子性，额好吧．
乖乖改成atomic_return_and_add(&(lk->own), 0)
重新运行，成功！
注意重新注释掉USE_TICKET_SPIN_LOCK,不然你最后的测试可能过不去，因为这个锁奇慢．

#### Round-Robin Scheduling
主要有几项规则：
1. 以环形的方式从envs[]数组中找RUNNABLE的环境
2. 如果原来有环境，从这个环境的下一个开始找起，如果是第一个环境，则从0开始找起
3. 只有当没有RUNNABLE了的环境的时候，才可以选默认的IDLE的运行
4. 状态是RUNNING的说明正运行在其他的CPU上面，不可以再次拿起来运行
```c
envid_t cur_id = (curenv != NULL)? ENVX(curenv->env_id) : 0;
for(i = (cur_id+1)%NENV; i != cur_id; i=(i+1)%NENV){
	if(envs[i].env_type != ENV_TYPE_IDLE && envs[i].env_status == ENV_RUNNABLE){
		env_run(&envs[i]);
	}
}
if(curenv && curenv->env_type != ENV_TYPE_IDLE && curenv->env_status == ENV_RUNNABLE){
	env_run(curenv);
}
```
做完这些后，在init.c中新开三个YIELD的环境
```c
#if defined(TEST)
	// Don't touch -- used by grading script!
	ENV_CREATE(TEST, ENV_TYPE_USER);
#else
	// Touch all you want.
	ENV_CREATE(user_yield, ENV_TYPE_USER);
	ENV_CREATE(user_yield, ENV_TYPE_USER);
	ENV_CREATE(user_yield, ENV_TYPE_USER);
	//ENV_CREATE(user_primes, ENV_TYPE_USER);
#endif // TEST*
```
#### System Calls for Environment Creation
下面我们将添加创造以及运行新环境的system call．
我们知道Unix系统中提供了一个fork()函数给用户来创建新的进程．他首先复制一份当前进程的拷贝，然后在这个新进程上面执行代码．
我们将要实现的调用接口如下：
* sys_exofork:
* sys_env_set_status:
* sys_page_alloc:
* sys_page_map:
* sys_page_unmap:
这里面大部分代码都比较简单，只需要遵照注释的提示就可以完成，而且大部分代码都是用于检测输入是否合法，所以这里略过不表．
我只说一下其中的两个，第一个是sys_exofork, 第二个是sys_page_map．
1. sys_exofork
这个比较难写是因为之前上一个lab里实现了sysenter来实现系统调用，
2. sys_page_map
这个难写是因为这个系统调用需要传进去５个参数，而我们之前实现的最多的也就是４个参数传递．这里需要对lib/syscall.c进行改写，先将第五个参数放在%esi上面
```c
asm volatile(
	"pushl %%ecx\n\t"
	"pushl %%edx\n\t"
	"pushl %%ebx\n\t"
	"pushl %%esp\n\t"
	"pushl %%ebp\n\t"
	"pushl %%esi\n\t"
	"pushl %%edi\n\t"
	 
     //Lab 3: Your code here
	"leal after_sysenter_label%=, %%esi\n\t"	/*return address is put into esi*/
	"pushl %%esp\n\t"			/*gcc inline assembler does not*/ 
						/*support directly loading values into ebp*/
    "popl %%ebp\n\t"
	"sysenter\n\t"
	"after_sysenter_label%=: \n\t"

    "popl %%edi\n\t"
    "popl %%esi\n\t"
    "popl %%ebp\n\t"
    "popl %%esp\n\t"
    "popl %%ebx\n\t"
    "popl %%edx\n\t"
    "popl %%ecx\n\t"
                 
    : "=a" (ret)
    : "a" (num),
      "d" (a1),
      "c" (a2),
      "b" (a3),
      "D" (a4),
	  "S" (a5)
    	: "cc", "memory");
```
但是％esi需要存储return address,所以一会儿我们要将%esi中的数据转移到栈上面．在trapentry.S文件中，改写syscall_handler．
```c
	pushl %esp
	pushl 0x4(%ebp)
	call syscall_wrapper
```
相当于为调用syscall_wrapper新添加了一个参数，通过%ebp + 4找到sysenter之前push到栈上面的%esi的值，也就是第五个参数的值．
接下来改写syscall_wrapper接口的工作比较简单，略过不表．
至此Part A 就结束了，通了一个宵才得了５分我也是十分崩溃．

### Part B: Copy-on-Write Fork
#### User-level page fault handling
一个用户级的copy-on-write的fork()函数需要知道在写保护页上面发生的page faults，一个Unix操作系统往往会根据page fault 发生所在区域的不同进行一些特殊的操作．
#### Setting the Page Fault Handler
##### Exercise 7
比较简单，和上一个联系增加系统调用的过程差不多．首先在syscall中添加dispatch的分发处理，然后实现sys_env_set_pgfault_upcall函数．

#### Normal and Exception Stacks in User Environments
首先如果一个环境想要支持用户级下的page fault　handling，都需要分配一块空间作为exception stack．当在user mode下发生page fault的时候，系统会重启用户环境在exception stack上面运行一段page fault handler的代码．
exception stack一开始只有一个页面大小，他的顶部在UXSTACKTOP的位置
当在exception stack栈上面运行的时候，page fault handler可以调用一些系统调用来修复内存映射关系．

#### Invoking the User Page Fault Handler
#### Exercise 8.
用户环境处理fault的这段时间可以叫做trap-time state.
如果发现当前环境没有注册自己的page fault handler，内核将会销毁当前环境．否则会首先在exception stack 上面push一个UTrapframe结构，用来在错误处理程序结束之后回到之前的上下文继续执行．如果是在错误处理程序中再次引发了page fault，　那么新的UTrapframe会建立在当前%esp下方，间隔32bit空行．因为
> The trap handler needs one word of scratch space at the top of the　trap-time stack in order to return.

#### User-mode Page Fault Entrypoint
##### Exercise 9.
根据注释的要求，我们需要填写的是调用完错误处理函数之后的现场恢复工作代码．不能直接使用`jmp`或者`call`.
我们应该把trap time的%eip压到trap time的栈上! 然后 我们要切换到那个栈 然后 'ret', 这样以来就可以重新执行之前出错的那一行代码．递归fault的情况下，记得我们之前在两个excption stack之间留了32bit的空档吗？现在就是他派上用场的时候了．

##### Exercise 10.
我们之前实现的那个sys_env_set_pgfault_upcall()系统调用是在内核中的，不是给用户直接使用的．
这个set_pgfault_handler会调用我们上面实现的函数，并且如果检测到这是第一次指定Page Fault handler的话还会为当前环境初始化exception stack.

#### Implementing Copy-on-Write Fork
##### Exercise 11.
fork()的基本控制流程是这样的：
1. 父进程环境将pgfault()注册为page fault处理函数
2. 父进程环境调用sys_exofork()来创建一个子进程环境
3. 将UTOP以下所有可写，或者是COW的页，给子进程环境在同一位置建立同样的映射但是是COW的页面．exception stack则比较特殊，因为我们的page fault处理函数就是运行在这上面的，所以他对应的那个页面不可以是只建立copy-on-write映射，而是必须给子进程环境分配一个新的页面来装exception stack
4. 父进程环境为子进程环境注册相同的page fault处理函数
5. 子进程环境状态改为RUNNABLE

### Part C: Preemptive Multitasking and Inter-Process communication
最终的这个部分我们将会修改JOS的调度模式为抢占式，然后实现进程环境之间的通信．

#### Clock Interrupts and Preemption
在原来的Round Robin调度模式下，其他环境进程只有等到当前进程主动放弃CPU资源的时候才有机会被调度运行起来，这样做的坏处就是一个恶意程序很容易通过一个循环就可以一直独占CPU，使得整个系统停掉．所以我们要实现抢占式的调度，为此我们需要支持硬件的时钟中断，让我们有机会重新获得CPU的控制权．

#### Interrupt discipline
外部中断（硬件中断）通过IRQ来标识，IRQ到IDT的映射是在picirq.c的pic_init()中建立的，IRQs [0-15]被映射到IDT [IRQ_OFFSET, IRQ_OFFSET+15]
在JOS中，做了简化，外部中断只有在用户态下才可以被接收，这一点是通过%eflags 寄存器的FL_IF位实现的．我们将会在CPU切换到用户态的时候重置%eflags寄存器，将IF位置为1，打开中断．
在bootloader的一开始，我们执行了一句cli，在开机过程中这屏蔽了中断．
##### Exercise 12.
1. 首先在trapentry.S和kenr/trap.c文件中注册中断处理函数
硬件中断并不会检查DPL,也不会push error code 到栈上
2. 修改kern/env.v中的env_alloc()保证用户态环境保持中断打开
```c
e->env_tf.tf_eflags |= FL_IF;
```
这之后其实还有一个需要注意的地方那就是sysenter会关闭中断，但是sysexit并不会开启中断哦，所以在sysexit之前加一句sti开启中断．
可以切换到内核态的路径还有一条那就是trap,trap处理函数推出之前会将栈上之前push进去的trapframe恢复（恢复了%eflags），所以这条路径也处理好了．

#### Handling Clock Interrupts
##### Exercise 13
只需要在trap_dispatch中增加新的处理代码就可以了，非常简单，注意不要忘记调用lapic_eoi()来确定中断处理完成，否则无法收到未来更多的中断．因为EOI被发送给PIC，PIC需要清掉ISR上面的mask.
```c
case IRQ_OFFSET + IRQ_TIMER:
    lapic_eoi();
	sched_yield();
	return;
```

#### Inter-Process communication(IPC)
JOS中的IPC采用共享内存的方式以及发送消息的模式，接受者调用sys_ipc_recv将自己挂起，直到有环境发消息给他之前都不会再运行．在该环境进程等待期间，任何环境进程都可以向他发送消息．发送者调用接口sys_ipc_try_send，如果目标环境进程没有调用过sys_ipc_recv将自己挂起，这个接口返回　-E_IPC_NOT_RECV．
发送消息的内容很短，包括一个32 bit的值，还可以选择添加一个单页的映射来进行页面共享．
发送者发送一个srcva给接收者，接受者接受时会指定一个dstva.系统会帮忙将发送者srcva映射到的物理页面在接收者环境进程中映射到dstva的位置，并且会将接受者环境的env_ipc_perm设置为接收到的页面的权限．这样两个环境之间就可以共享一个物理页面了．

##### Exercise 14.
1. 实现sys_ipc_recv和sys_ipc_try_send，唯一需要注意的就是调用envid2env的时候，checkperm设置成0就可以了，因为这个调用不需要两个进程之间有父子关系之类的，任何两个进程之间都可以使用．　另外一个用户调用recv以后 会陷入内核 并且 not runnable,再次运行则会通过env_yield去调用env_run走pop_tf 所以 这里我们要让recv正常返回 需要e->env_tf.tf_regs.reg_eax = 0
2. ipc.c:注释比较详尽，唯一要注意的是两个函数都是当pg为NULL的时候，不能用0作为地址调用系统调用，因为0将是一个合法的参数，应该用大于UTOP的值．

### Challenge
我选择的是实现优先级调度
效果如下所示，可以看到高优先级的进程被优先调度起来了．
我在inc/env.h文件定义了一个宏　USE_PRIORITY_SCHEDUALER, 助教如果想要测试这个challenge的话可以进入把注释取消掉，然后运行
make qemu　就可以测试了．
这个宏如果被注释掉的话make qemu将会运行primes那个程序
定义了的话会运行我写的４个测试文件，每个程序开启一个不同优先级的进程运行并输出一些信息．

效果：
```c
SMP: CPU 0 found 1 CPU(s)
enabled interrupts: 1 2
[00000000] new env 00001000
[00000000] new env 00001001
[00000000] new env 00001002
[00000000] new env 00001003
[00000000] new env 00001004
[00000000] new env 00001005
[00000000] new env 00001006
[00000000] new env 00001007
[00000000] new env 00001008
[00000000] new env 00001009
[00000000] new env 0000100a
[00000000] new env 0000100b
[00001009] Super Priority Env is Running
[00001009] Super Priority Env is Running
[00001009] Super Priority Env is Running
[00001009] exiting gracefully
[00001009] free env 00001009
[00001008] High Priority Env is Running
[00001008] High Priority Env is Running
[00001008] High Priority Env is Running
[00001008] exiting gracefully
[00001008] free env 00001008
[0000100a] Low Priority Env is Running
[0000100a] Low Priority Env is Running
[0000100a] Low Priority Env is Running
[0000100a] exiting gracefully
[0000100a] free env 0000100a
[0000100b] Normal Priority Env is Running
[0000100b] Normal Priority Env is Running
[0000100b] Normal Priority Env is Running
[0000100b] exiting gracefully
[0000100b] free env 0000100b
No more runnable environments!
Welcome to the JOS kernel monitor!
Type 'help' for a list of commands.
K> 
```
实现过程：
首先在inc/env.h里面，我为Env这个结构新添加了一个字段用来表示优先级　uint32_t env_priority
并且用宏定义了一些优先级．
在env_alloc()函数中，新建一个环境进程的时候优先级默认被设置为NORMAL_PRIORITY.
然后添加了一个新的系统调用　sys_env_set_status()用来让用户设置进程的优先级．这部分需要修改的文件有
inc/syscall.h, inc/lib.h, kern/syscall.h, kern/syscall.c, lib/syscall.c
最后在sched.c中我实现了一种优先级的调度方式如下：
```c
#ifdef USE_PRIORITY_SCHEDUALER
	uint32_t j;
	for(j = SUPER_PRIORITY; j <= LOW_PRIORITY; j++){
		for(i = (cur_id+1)%NENV; i != cur_id; i=(i+1)%NENV){
			if(envs[i].env_type != ENV_TYPE_IDLE && envs[i].env_status == ENV_RUNNABLE){
				if(envs[i].evn_priority == j){
					env_run(&envs[i]);
				}
			}
		}
	}

#else
	for(i = (cur_id+1)%NENV; i != cur_id; i=(i+1)%NENV){
		if(envs[i].env_type != ENV_TYPE_IDLE && envs[i].env_status == ENV_RUNNABLE){
			env_run(&envs[i]);
		}
	}
#endif
```
平时不采用这种调度方式是因为这样复杂度变成原来的4倍，所以平时还是使用普通的调度方式

我自己写的测试文件是priorityXXXX.c，过程比较简单，就是首先设置一下自己的优先级，然后循环输出一些内容．
例如priorityHIGH.c就实现如下：
```c
#include <inc/lib.h>
#include <inc/env.h>

void umain(int argc, char **argv)
{
	sys_env_set_priority(0, HIGH_PRIORITY);
	int i;
	int n = 3;
	for (i = 0; i < n; i++) {
		cprintf("[%08x] High Priority Env is Running\n", sys_getenvid());
	}
	return;
}
```

然后我们老办法在init.c中初始化的时候开四个进程跑跑看就知道了．当然在此之前还要修改kern/Makefrag文件将新的测试文件包括进去
```c
# Binary files for LAB4 Challenge: priority scheduler
KERN_BINFILES += 	user/priorityHIGH \
			user/priorityLOW \
			user/prioritySUPER \
			user/priorityNORMAL
```