#**JOS LAB 1: Booting a PC** 

**目录**
[TOC]
## **代码部分设计**
### Exercise 8
>We have omitted a small fragment of code - the code necessary to print octal numbers using patterns of the form "%o". Find and fill in this code fragment. Remember the octal number should begin with '0'.
* 要完成这道题首先需要通读 kern/printf.c, lib/printfmt.c 和  kern/console.c 这三个文件，具体这三个文件的关系我在后面非代码部分也有介绍，这里不再赘述，只讲解代码细节。
先放代码

```cpp
case 'o':
	// Replace this with your code.
	// display a number in octal form and the form should begin with '0'
	putch('0', putdat);
	num = getuint(&ap, lflag);
	base = 8;
	goto number;
	break;
```
这道题目非常的简单，目的应该只是想让大家热热身，基本上参照下面pointer case的写法就可以很快速的写好。
但是要想顺利完成后面所有的练习，这里最好仔细阅读一下`vprintfmt()`这个函数。这个函数是实现格式化打印字符串的主要功能实现函数，整个函数的流程如下所示供参考：
```flow
st1=>start: 开始
op2=>operation: 直接打印字符
op3=>operation: 识别占位符并处理
cond=>condition: 是否占位符标示%
st1->op2->cond
op3->op2
cond(yes)->op3
cond(no)->op2

```


### Exercise 9
>You need also to add support for the "+" flag, which forces to precede the result with a plus or minus sign (+ or -) even for positive numbers.

我们可以先在monitor模块中测试一下如果没有实现 `+`flag的时候会打出什么东西。
在monitor()这个函数中加入这样一句
```cpp
cprintf("test %+d.\n"， 1024);
```
读者可以自己试一下，这个时候启动qemu应该打印出来`test %+d`。原因是这个时候在reswitch这段代码中还不能够识别`+`标示，所以会跳转到`default：`然后退出处理占位符的循环，然后将后面的部分都当做普通字符串直接打印出来。所以我的代码主要添加了两个地方的逻辑：
* 首先是需要在`reswitch`中识别`+`标志
```cpp
case '+':
	padc = '+';
	goto reswitch;
```
* 然后利用刚才遇到`+`flag存储的padc这个变量，在处理%d的逻辑中打印符号
```cpp
// (signed) decimal
case 'd':
	num = getint(&ap, lflag);
        if ((long long) num < 0) {
	    putch('-', putdat);
	    num = -(long long) num;
	}else{
	    if(padc == '+')
		    putch('+', putdat);
	}
	base = 10;
	goto number;
```
后面打印数字的部分领用原来的逻辑就可以了

### Exercise 13
>Implement the backtrace function

接下来三道题都主要是在monitor模块中进行编码。所以在开始做之前让我们先来看一看这个模块。
流程图如下所示：
```flow
st=>start: monitor
op1=>operation: 打印提示符,等待用户输入
op2=>operation: 调用runcmd( )函数
op3=>operation: 分析命令
op4=>operation: 交由具体命令的实现函数处理
cond=>condition: 是否有输入?
st->op1->cond
cond(yes)->op2
cond(no)->op1
op2->op3->op4->op1
```
在这个模块有一个全局变量使用来存储所有命令以及对他们描述的Command指针数组，Command结构的实现是这样的
```cpp
struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};
```
可以看出这个结构中除了比较常规的指令名字和描述，还存储了一个函数指针，这个指针就是在runcmd函数中解析出是那一条指令之后用来找到具体实现逻辑的导航仪。
我们先在commands全局数组中添加要实现的命令，由于下面两道题都是要求添加指令，这里笔者就一次性添加所有的指令了。这里Commands结构中desc这个变量是用来在help指令时打印出来的帮助信息。
```cpp
static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "backtrace", "Display information about the current stack backtrack", mon_backtrace },
	{ "time", "Display the run time of a special command", mon_time },
};
```
可以看到我们为backtrace实现一个mon_backtrace函数，这个函数没有什么难的，利用基本的栈的知识就可以。
这里注意第一个参数是ebp+8而不是加4。然后注意指针的加法移动多少是根据指针的类型决定的，放一下取第一个参数的代码，其余大同小异
```cpp
uint32_t first_arg = *((uint32_t*)ebp + 2);
```
要回溯整个栈需要知道两点：
* %ebp被初始化的第一个值是0x0,在entry.S中可以找到
* 栈上最顶端存储了上面一个栈的%ebp的值

简单画一下栈的结构：
|...|
|:---|
|last stack|
|...|
|arg2|
|arg1|
|old %ebp|
|new stack|
|...|


### Exercise 14
这道题为了打印出debug信息，需要先阅读一下kdebug这个模块，其实注释已经说的很明白了。调试信息存储在`Stab`这个结构组成的表中
** stab的结构
```
// Entries in the STABS table are formatted as follows.
struct Stab {
	uint32_t n_strx;	// index into string table of name
	uint8_t n_type;         // type of symbol
	uint8_t n_other;        // misc info (usually empty)
	uint16_t n_desc;        // description field
	uintptr_t n_value;	// value of symbol
};
```
这个表中从左到右按地址存储了所有文件、函数的信息，stab_binsearch这个函数的逻辑是从两头向中间用地址去搜索一个`Stab`，如果左右两个指针在中间会和了则说明没有找到，如果找到了左边的指针会指向包含这个地址的`stab`，而右边的指针则指向下一个`stab`之前的位置，然后通过切换到一种更具体的类型继续查找（比如文件切换到函数），最后就可以具体找到在哪个文件哪个函数第几行。
我讲的可能还不是很清楚，详细可以参照Kdebug.c文件中的注释。

我们要做的事情也很简单，因为之前查找文件，查找函数的部分已经完成好了，我们只需要照葫芦画瓢补全查找行号的逻辑就可以了
```c
    // search for line
	stab_binsearch(stabs, &lline, &rline, N_SLINE, addr);
	if(lline <= rline){
		info->eip_line = stabs[lline].n_desc;
	}else{
		info->eip_line = -1;
	}
```
搜寻完信息之后在上一道题的mon_backtrace中将信息打印出来就好啦！

### Exercise 15
最后一道题啦！说实话笔者这个实验做了两天了还没做完，精力全都花在写文档上面了。。。

根据文档的提示，google了一下rdtsc，是一条可以获取CPU周期数的指令，首先写一个函数专门用来获取周期数方便复用。
```c
static uint64_t
rdtsc(){
	unsigned int lo, hi;
	__asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d"(hi));
	return ((uint64_t)hi << 32) | lo;
}
```
然后老方法实现一个mon_time函数用来处理time命令，具体实现就是先获取周期数，然后调用后面的命令对应的函数，结束后再获取一次周期数然后做减法。
写完之后我们可以测试一下，看一看递归time命令会发生什么。
```cpp
time time kerninfo
```

```c
K> time time kerninfo
Special kernel symbols:
  entry  f010000c (virt)  0010000c (phys)
  etext  f0101d91 (virt)  00101d91 (phys)
  edata  f0112300 (virt)  00112300 (phys)
  end    f0112960 (virt)  00112960 (phys)
Kernel executable memory footprint: 75KB
Kerninfo cycles: 06680208
Kerninfo cycles: 07624067

```

完结撒花！！


## **其余练习部分解答**
### Exercise 4

> Q1: At what point does the processor start executing 32-bit code? What exactly causes the switch from 16- to 32-bit mode?
``` c
[   0:7c2d] => 0x7c2d:	ljmp   $0x8,$0x7c32
```
执行完这句长跳转之后，gdb输出这样一句话：
``` c
The target architecture is assumed to be i386
```

说明这里是处理器正式进入32位的保护模式，开始执行32-bit的代码的分界处。
原因是这句

> Q2:What is the last instruction of the boot loader executed, and what is the first instruction of the kernel it just loaded?

bootloader中所执行的最后一句指令是
``` c
call   *0x10018
```
对应于boomain.c文件里的就是
``` c
   ((void (*)(void)) (ELFHDR->e_entry))();
```
这一句。这一句的含义是调用了刚刚从磁盘中加载到内存中的代码里的e_entry()这个函数。
kernel中的第一条被执行的指令是这条：
``` c
=> 0x10000c:	movw   $0x1234,0x472
```


> Q3: How does the boot loader decide how many sectors it must read in order to fetch the entire kernel from disk? Where does it find this information?

在bootmain（）这个函数中，我们看到第一句是这样的
``` c
readseg((uint32_t) ELFHDR, SECTSIZE*8, 0);
/* SECTSIZE = 512  */
```
也就是首先会读取磁盘上的第一个4KB大小的页。这个页中的存储l一个ELF可执行文件的头部。通过解析这个ELF文件，我们就可以知道如何将kernel加载到内存中去。
ELF文件的结构如下所示：

![ELF file structure](ELF.png)

从图中我们可以看出，ELF文件大体上可以分成四个部分：
* ELF header：描述整个文件的组织
* Program Header Table:描述文件中各种segments，用来告诉系统如何创建进程映像。
* 中间是各种数据段
* 最后尾部的section header table描述了目标文件节。

这里我们主要是用到了ELF header和 Program Header Table这两个数据结构，我们来看一下这两个数据结构在elf.h中的定义（对其中要用到的变量我进行了注释）：

``` c
struct Elf {
    uint32_t e_magic;   // must equal ELF_MAGIC
    uint8_t e_elf[12];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;   // 程序的入口点
    uint32_t e_phoff;   // Program header tables在ELF文件中的偏移量
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;   // program header tables的数量
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct Proghdr {
    uint32_t p_type;    // 段的类型
    uint32_t p_offset;  // 在文件中这个段的起始位置
    uint32_t p_va;      
    uint32_t p_pa;      // 加载到内存中的物理地址
    uint32_t p_filesz;
    uint32_t p_memsz;   // 这个段的大小（byte）
    uint32_t p_flags;
    uint32_t p_align;
};
``` 
有了这些信息，bootmain()函数就可以将ELF文件中的代码段数据段加载到内存中去了。而我们的问题结合源代码也不难得出答案：
``` c
    // load each program segment (ignores ph flags)
    ph = (struct Proghdr *) ((uint8_t *) ELFHDR + ELFHDR->e_phoff);
    eph = ph + ELFHDR->e_phnum;
    for (; ph < eph; ph++)
        // p_pa is the load address of this segment (as well
        // as the physical address)
        readseg(ph->p_pa, ph->p_memsz, ph->p_offset);


```
通过遍历Program header tables中的每一个program header，我们一个一个地磁盘上内核的ELF可执行文件的每一个代码段数据段。每一个段的大小在program header中都由p_memsz指出，整个kernel的大小自然而然也就知道了。但是这里得到的是byte为单位的大小，具体计算需要读取多少个sector的逻辑是在readseg()函数中实现的：
``` c
    // translate from bytes to sectors, and kernel starts at sector 1
    offset = (offset / SECTSIZE) + 1;

```

### Exercise 5
> Reset the machine (exit QEMU/GDB and start them again). Examine the 8 words of memory at 0x00100000 at the point the BIOS enters the boot loader, and then again at the point the boot loader enters the kernel. Why are they different? What is there at the second breakpoint? (You do not really need to use QEMU to answer this question. Just think.)

shell中运行
``` c
objdump -h obj/kern/kernel
``` 
输出信息如下所示：
``` c
obj/kern/kernel：     文件格式 elf32-i386

节：
Idx Name          Size      VMA       LMA       File off  Algn
  0 .text         00001a91  f0100000  00100000  00001000  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
  1 .rodata       00000780  f0101aa0  00101aa0  00002aa0  2**5
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  2 .stab         000039b5  f0102220  00102220  00003220  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  3 .stabstr      0000197b  f0105bd5  00105bd5  00006bd5  2**0
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  4 .data         0000a300  f0108000  00108000  00009000  2**12
                  CONTENTS, ALLOC, LOAD, DATA
  5 .bss          00000660  f0112300  00112300  00013300  2**5
                  ALLOC
  6 .comment      00000034  00000000  00000000  00013300  2**0
                  CONTENTS, READONLY
```
从LMA那一列我们可以看出.text段的在内存中起始位置就是物理地址0x00100000,也就是说bootloader在bootmain()函数中将内核的ELF可执行文件中的代码段.text加载到了内存中这个位置，所以在两次读取这个位置得到的结果会不一样。


### Exercise 7
> What is the first instruction after the new mapping is established that would fail to work properly if the old mapping were still in place? Comment out or otherwise intentionally break the segmentation setup code in kern/entry.S, trace into it, and see if you were right.

``` c
 73     movl    $0x0,%ebp
```
我的做法是注释掉kern/entry.S中的这一段的几条指令
``` c
 54     # Load the physical address of entry_pgdir into cr3.  entry_pgdir
 55     # is defined in entrypgdir.c.
 56     movl    $(RELOC(entry_pgdir)), %eax
 57     movl    %eax, %cr3
 58     # Turn on paging.
 59     movl    %cr0, %eax
 60     orl $(CR0_PE|CR0_PG|CR0_WP), %eax
 61     movl    %eax, %cr0


```

这段指令要做的是打开分页机制，并且将CR3置位设置好的页表的基地址，从而建立虚拟地址[KERNBASE , KERNBASE+4MB) 到 物理地址 [0, 4MB)的映射。下面这两条指令会把EIP置成高地址(VA)，如果没有这层映射，接下来的那条指令就会因为读不到指令而出错

```c
 66     mov $relocated, %eax
 67     jmp *%eax 
```

### Exercise 9
> 1.Explain the interfase between printf.c and console.c. Specifically, what function does console.c export? How is this function used by printf.c
printf.c中只调用了cputchar()这个函数。
console.c对外提供的函数有cputchar(), iscons()和getchar()三个函数
通过在kern目录下运行以下几条命令可以证明。
``` c
    grep -r "cputchar" *
    grep -r "iscons" *
    grep -r "getchar" *
```

> 2.Explain the following from console.c:
``` c
if (crt_pos >= CRT_SIZE) {
	int i;
	memmove(crt_buf, crt_buf + CRT_COLS, (CRT_SIZE - CRT_COLS) * sizeof(uint16_t));
    for (i = CRT_SIZE - CRT_COLS; i < CRT_SIZE; i++)
		crt_buf[i] = 0x0700 | ' ';

	crt_pos -= CRT_COLS;
}
```
先说最终实现的结果：如果屏幕满了就向下滚动一行。
下面进行分析：
CRT_SIZE 的定义在console.h中可以找到
```c
#define CRT_SIZE	(CRT_ROWS * CRT_COLS)
```
看到这里基本可以猜到CRT_SIZE代表了整个屏幕可以显示的字数
结合上下文可知crt_pos表示当前输出到第几个字了，所以if判断的就是当前屏幕是否已经输出满了。
接下来
```c
    memmove(crt_buf, crt_buf + CRT_COLS, (CRT_SIZE - CRT_COLS) * sizeof(uint16_t));
```
这句的作用就是将从第二行开始到末尾的数据在buffer中向上移动一行。
紧跟着的for循环将最后一行从屏幕中清除掉。最后将crt_pos的位置也向上更新一行。
 
```c
int x = 1, y = 3, z = 4;
cprintf("x %d, y %x, z %d\n", x, y, z);
```
>3.1 In the call to cprintf(), to what does fmt point? To what does ap point?
fmt指向字符串，ap指向余下的所有参数。

>3.2 List(in order of execution) each call to cons_putc, va_arg, and vcprintf. For cons_putc, list its argument as well. For va_arg, list what ap points to before and after the call. For vcprintf list the values of its two arguments.

```c
#0  cons_putc (c=120) at ./inc/x86.h:48
#1  0xf0100728 in cputchar (c=120) at kern/console.c:458
#2  0xf01009a5 in putch (ch=120, cnt=0xf010fe0c) at kern/printf.c:12
#3  0xf0100e79 in vprintfmt (putch=0xf0100993 <putch>, putdat=0xf010fe0c,
    fmt=0xf0101e41 "x %d, y %x, z %d\n", ap=0xf010fe44 "\001") at lib/printfmt.c:103
#4  0xf01009d1 in vcprintf (fmt=0xf0101e41 "x %d, y %x, z %d\n", ap=0xf010fe44 "\001")
    at kern/printf.c:21
#5  0xf01009e8 in cprintf (fmt=0xf0101e41 "x %d, y %x, z %d\n") at kern/printf.c:32

```

>4.Run the following code, what is the output?
```c
unsigned int i = 0x00646c72;
cprintf("H%x Wo%s", 57616, &i);
```
输出结果是 He110 World

* Explain:
57616转化成16进制是 0xe110, 
而字符串在编译后的保存形式出了大小端和整数是一样的，都是以值的形式保存.
这里0x64, 0x6c, 0x72对应的ASCII字符分别是"d", "l", "r",并且存储是以小端法存储的。所以这里是输出的是 rld\0

>if the x86 were instead big-endian what would you set i to in order to yield the same output? Would you need to change 57616 to a different value?
* 答：unsigned int i = 0x726c6400
57616并不需要改变，小端法影响的只是存储在内存中的数据。

> 5。 In the following code, what is going to be printed after 'y=' ? (note: the answer is not a specific value.) Why does this happen?
```c
    cprintf("x=%d y=%d", 3);
```
* 会输出 x=3 y=?
其中？代表那个地方是一个不确定的值，原理是调用cprintf之前会将3先压栈，然后在cprintf的栈中利用 %ebp + 8 取出传递进来的参数3，但是这里字符串中多指定了一个%d占位符，于是会用 %ebp+12 取得第二个参数，这个值具体是多少由调用cpirntf的栈长什么样子决定。

>6. Let's say that GCC changed its calling convention so that it pushed arguments on the stack in declarationorder, so that the last argument is pushed last. How would you have to change cprintf or its interface so that it would still be possible to pass it a variable number of arguments?
可以修改cprintf()的调用形式，在后面添加一个参数cnt，需要用户输入传入的参数的个数，然后在cprintf函数中根据cnt这个参数计算出第一个参数的位置，正序取出几个参数。


### Exercise 11
>Determine where the kernel initializes its stack, and exactly where in memory its stack is located. How does the kernel reserve space for its stack? And at which "end" of this reserved area is the stack pointer initialized to point to?

```c
relocated:

	# Clear the frame pointer register (EBP)
	# so that once we get into debugging C code,
	# stack backtraces will be terminated properly.
	movl	$0x0,%ebp			# nuke frame pointer

	# Set the stack pointer
	movl	$(bootstacktop),%esp
    # now to C code
	call	i386_init
```
在entry.S中的relocated部分进行了初始化，精确的位置可以在kernel.asm中找到
```c
relocated:

	# Clear the frame pointer register (EBP)
	# so that once we get into debugging C code,
	# stack backtraces will be terminated properly.
	movl	$0x0,%ebp			# nuke frame pointer
f010002f:	bd 00 00 00 00       	mov    $0x0,%ebp

	# Set the stack pointer
	movl	$(bootstacktop),%esp
f0100034:	bc 00 00 11 f0       	mov    $0xf0110000,%esp

	# now to C code
	call	i386_init
f0100039:	e8 56 00 00 00       	call   f0100094 <i386_init>
```
可以看到%ebp寄存器被清空，然后设置%esp的初始的精确位置在 0xf0110000，紧接着调用了一条call指令，在i386_init中首先会将%ebp(0x0)压栈，然后将%esp(0xf0110000)的值赋给%ebp。这就是产生了真正意义上的第一个栈，也就是第一个进程init进程的栈，栈的位置在虚拟内存空间的高地址处0xf0110000。

如何给栈保留空间：在relocated部分代码中我们看到%esp的初始化是通过这一句来完成的
``` c
movl	$(bootstacktop),%esp
```
结合 objdump -h kern得到的段的信息
``` c
4 .data         0000a300  f0108000  00108000  00009000  2**12
                  CONTENTS, ALLOC, LOAD, DATA
```
可以看出栈的初始地址在内存中kern的data段之内，在data段的末尾位栈预留了位置。


%ebp指向栈的底端（高地址），%esp指向栈的顶端(低地址)。在使用过程中栈会向低地址扩张，stack pointer始终指向栈的顶端（低地址的那一端）。


### Exercise 12
> To become familiar with the C calling conventions on the x86, find the address of the test_backtrace function in obj/kern/kernel.asm , set a breakpoint there, and examine what happens each time it gets called after the kernel starts. How many 32-bit words does each recursive nesting level of test_backtrace push on the stack, and what are those words?

下面简单的画一下test_backtrace的栈
|stack|
|-----------------------------------|
|old ebp							|
|old ebx							|
|reserve space  （0xc）				|
|......								|
|argument x							|
|address of string					|
|arguemnt for next call (x-1)		|






