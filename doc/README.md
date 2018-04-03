#**JOS LAB 1: Booting a PC** 
姓名：王涛
学号：515030910083

**目录**
[TOC]

> 本次实验中基本所有的代码实现都集中在 `pmap.c`文件中，接下来我将按照每个Exercise 任务的顺序，依次介绍每个任务中实现的函数以及添加的代码，中间会穿插一些对mem_init()函数逻辑的介绍。

##**Part 1: Physical Page Management**
这部分的任务是实现跟踪记录那些物理页是空闲的，哪些的物理页是已经被分配了的。JOS是以页位最小粒度来管理整个物理地址空间的。实现方法是使用了一个链表的结构来记录这些信息，每一个页对应链表上的一个节点。需要用到的数据结构就是下面这个
```c
static struct Page *page_free_list;	// Free list of physical pages
```
其中每一个节点都是一个叫做Page的结构：
```c
struct Page {
	struct Page *pp_link;
	uint16_t pp_ref;
};

```
pp_link是指向链表上下一个节点的指针，pp_ref是一个计数器，用来记录有多少个虚拟地址空间中的页映射到这个物理页上面，当pp_ref为0的时候，就说明这个物理页是free的，没有被映射到虚拟地址空间中去。

在`Part 1`中，我们需要做的就是利用这个链表的数据结构，来实现一个物理页的分配器，方便后面建立虚拟内存的时候使用。

### Exercise 1.
JOS系列lab的特点都是不明确告诉我们需要做什么事情，需要自己去阅读代码以及注释发现问题。但是题目中已经非常明确的告诉我们需要实现哪些函数了。所以后面要做的就是跟寻代码中注释的指引一个一个地完成每一个要求的函数。当正确了实现所有的函数之后。你的JOS应该可以正确通过`mem_init`中的`check_page_free_list()` 以及 `check_page_alloc()`两个测试函数。

在开始介绍具体代码的实现之前，因为这是第一道题，所以在开始写代码之前，我们不妨来看一看这次实验的整体结构设计。在`kern/init.c`这个文件中，我们可以看到，相比较lab1时候的代码，初始化部分的
```c
test_backtrace(5);
```
这一句被替换成了
```c
mem_init();
```
很明显这里就是整个lab2实验代码部分的入口。我们接下来要做的所有事情都和这个函数有关。可以发现，基本上我们要实现的所有函数都会在`mem_init`中被调用。所以接下来在函数的实现中我们穿插进对于`mem_init`函数逻辑的解说。
好啦，让我们开始干活！

#### boot_alloc()
在调用我们要实现的第一个函数boot_alloc之前，在mem_init中先是执行了`i386_detect_memory`这个函数。可以看到在这个函数中主要是得到两个全局变量的值，他们分别是 **npages_basemem** 和 **npages_extmem**，这两个变量内存储的分别是机器上物理内存的基本内存页和扩展内存页的个数。这两个参数决定我们的机器上总共物理内存页的个数`npages`，在后面会用到。
接下来boot_alloc函数就被调用了。
这个函数是在虚拟内存被建立起来之前用来代替`page_alloc()`进行物理内存分配的，在页表机制被建立起来之后就不应该再被使用了。
它接受一个参数用来指定要分配的字节数，然后分配整数页的物理内存出来。
在函数内部有一个静态变量`next_free`用来记录当前机器上物理页分配到哪里了。这个变量的初始化过程注释中有解释，用了一个end标志来获得被加载到内存中kernel的bss段的末尾位置，这个位置也就是链接器进行链接的时候没有链接给任何kernel数据或者代码的位置。这个位置网上都是没有被内核占用的空间。

实现的时候需要注意的是要检查参数，并且一定要分配整数个数的物理页。
实现这一点可以使用在`types.h`中定义的两个宏，之所以定义成宏我觉得是因为这两个功能被使用的频率都非常高，而函数调用的overhead较高，定义成宏更轻量。
```c
// Rounding operations (efficient when n is a power of 2)
// Round down to the nearest multiple of n
#define ROUNDDOWN(a, n)						\
({								\
	uint32_t __a = (uint32_t) (a);				\
	(typeof(a)) (__a - __a % (n));				\
})
// Round up to the nearest multiple of n
#define ROUNDUP(a, n)						\
({								\
	uint32_t __n = (uint32_t) (n);				\
	(typeof(a)) (ROUNDDOWN((uint32_t) (a) + __n - 1, __n));	\
})
```
具体实现这里不再赘述，比较简单，想看的话可以参考代码。
`mem_init`调用boot_alloc是要分配出一个物理页出来用来存放内核页表，基地址存放在一个全局变量`kern_pgdir`里面。这里说一下JOS中页表结构的特点，这部分在`memlayout.h`的注释中有介绍。
在MMU翻译的过程中，第一级页表也叫作页目录，第二级页表才是真正的页表。
在JOS中，对于页目录（PD）和页表（PT）并没有明显的区分，这样做有两个好处:
1.  所有的PTE的存放地址都可以通过一个在entry.S中设立的VPT这个基地址和index计算得出。
    比如说page number 为 N 的页对应的PTE就存放在vpt[N]的位置
    这里注意要理解不管是页表还是页目录，他们都是存放在物理页中的，他们也会有自己的page number
2. 页目录的地址可以通过VPT计算得出：vpd = (VPT + (VPT >> PGSHIFT))
    PGSHIFT 的 值是12，VPT >> 12 也就是以虚拟地址VPT起始的页的page number。
    vpd这个页在页表中也有一项PTE，MMU通过这个PTE就可以找到页目录存放的页的起始物理地址
    所以VPD指向的就是这个位置，注意VPD是虚拟地址。

实际上页目录的某一个PDE对应的PTSIZE空间里面存放的就是页目录和所有页表结构。这PTSIZE大小的空间起始于VPT这个位置。
这里理解起来稍微有点tricky，需要仔细揣摩。

理解了上面我写的内容，就可以理解`mem_init`中分配完存储页目录的页之后的那一句代码了
```c
kern_pgdir[PDX(UVPT)] = PADDR(kern_pgdir) | PTE_U | PTE_P;
```
这里其实就是在设置PDE中映射到存放页表和页目录的1024个物理页大小空间的那一项entry的访问权限。
其中UVPT的值是0xef400000，定义在`memlayout.h`之中。于是我们可以知道，此时在虚拟内存中，页目录和页表存储在[0xef400000, 0xef400000 + PTSIZE) 这个范围之内。

接下来`mem_init`又使用`boot_alloc`给跟踪记录物理页分配情况的链表结构分配了一些物理页。
这一段要求我们来填写：
```c
size_t p_size = sizeof(struct Page);
pages = boot_alloc(npages * p_size);
memset(pages, 0, npages*p_size);
```
#### page_init()
通过上面的代码我们已经建立起了页表结构，也为跟踪物理页分配情况的free_list链表结构上面的节点分配了内存空间。
这之后的所有内存管理都需要调用我们接下来实现的三个功能函数，不再使用之前的`boot_alloc`了。

此时free_list上面的节点虽然都分配了空间，但是free_list结构并没有被建立起来。
这个函数就是要初始化我们刚刚给分配好内存空间的free_list,因为在此之前我们已经使用了一些页，用来放置内核的代码，数据，以及页表结构和我们的`Page`结构，
所以要根据当前物理页的分配情况来初始化free_list结构。
分配的原则是这样的：
1. 第一个页（page number = 0）被保留作他用 
2. 其余base memory中的物理页是free的
3. IO hole， 不能被分配
4. extended memory中尚未分配的内存（可以传入boot_alloc(0)获得起始地址）

#### page_alloc()
实现分配一个物理页的功能。注意我们并不在分配的时候增加pp_ref计数器的值，也就是说出了这个函数物理页还是free的，
需要调用的函数自己显式增加pp_ref计数器。
提示里告诉我们可以使用`page2kva`和`memset`，`memset`是用来将物理页中的内容清零的。
我们来看一下`page2kva`这个函数。
过程大致就是先根据page number取得页的物理起始地址，然后因为此时真正的页表翻译机制还没有建立起来，用的还是之前的简单映射，
也就是直接加一个KERNBASE。所以这样就可以直接取得页的虚拟起始地址。之所以要这样做是因为程序中使用的必须是虚拟地址，因为此时页机制已经打开了。
```c
static inline void*
page2kva(struct Page *pp)
{
	return KADDR(page2pa(pp));
}

static inline physaddr_t
page2pa(struct Page *pp)
{
	return (pp - pages) << PGSHIFT;
}

struct Page *pages;		// Physical page state array

/* This macro takes a physical address and returns the corresponding kernel
 * virtual address.  It panics if you pass an invalid physical address. */
#define KADDR(pa) _kaddr(__FILE__, __LINE__, pa)

static inline void*
_kaddr(const char *file, int line, physaddr_t pa)
{
	if (PGNUM(pa) >= npages)
		_panic(file, line, "KADDR called with invalid pa %08lx", pa);
	return (void *)(pa + KERNBASE);
}
```

分配的过程是先从free_list中取出一个空闲的物理页。然后根据参数判断是否需要清零。

#### page_free()
实现释放一个物理页的功能。
首先检查一下是否pp_ref是否已经减到了0，该物理页已经没有人使用了，然后把该页放置到free_list上面去。



##**Part 2: Virtual Memory**

### Exercise 4.
正确实现了这一部分之后，`mem_init`中应该可以通过check_page()的检查。
#### pgdir_walk()
函数原型如下：
```c
pte_t *
pgdir_walk(pde_t *pgdir, const void *va, int create);
```
该函数接受一个指向页目录的指针，以及一个虚拟地址，函数内部模拟MMU翻译虚拟地址的过程，最后返回该虚拟地址所在的页的PTE。
需要走两级页表，第一级是页目录，找到所在的页表，在第二级页表中找到对应的PTE。
需要注意的是，PTE所在的页表可能是第一次被使用，所以在页目录中相应的PDE没有被初始化过。
所以函数还接受一个create属性，表示调用函数在这种情况下是否希望该函数主动创建盛放需要的页表的页并且设置PDE。
提示里提示使用的几个函数。page2pa()我们在上面已经见识过了，这里不再介绍。

* 我们之前已经介绍过了JOS的页表及页目录的结构了，容易知道va所对应的pde可以通过下面的方法取得。
```c
pde_t * pde = pgdir + PDX(va);
```
* 另外一个需要注意的是，内核和用户态程序一样无法绕过页表的地址翻译机制，所以同样无法直接使用物理地址。
    在取得了pde后，pde里存放的pt的地址是物理地址，没办法直接使用，必须要翻译成虚拟地址。

```c
pte_t * pt = (pte_t *)KADDR(PTE_ADDR(*pde));
pte_t * pte = pt + PTX(va);
```

#### boot_map_region()
函数原型如下
```c
static void
boot_map_region(pde_t *pgdir, uintptr_t va, size_t size, physaddr_t pa, int perm);
```
该函数实现的功能是将[va, va+size)范围的虚拟内存，映射到[pa, pa+size)。
熟悉页表机制的话，应该可以很快想到只需要通过pgdir_walk获取到va对应的PTE，然后修改PTE里面的值就可以了。
```c
pte_t * pte = pgdir_walk(pgdir, (void *)va, 1);
*pte = pa | perm | PTE_P;
```
#### page_lookup()
函数原型如下：
```c
struct Page *
page_lookup(pde_t *pgdir, void *va, pte_t **pte_store);
```
给定一个虚拟地址，返回对应的PTE，存储到pte_store指向的内存，还需要返回对应的`Page`结构。
如何将从PTE中获取的页的物理地址转换为对应的`Page`结构呢？
提示里面给出了答案，使用pa2page函数，内部逻辑其实就是通过物理地址得到物理页号，以此为偏移量在pages中找到对应的`Page`
```c
static inline struct Page*
pa2page(physaddr_t pa)
{
	if (PGNUM(pa) >= npages)
		panic("pa2page called with invalid pa");
	return &pages[PGNUM(pa)];
}
```
#### page_remove()
函数原型如下：
```c
void
page_remove(pde_t *pgdir, void *va)
```
取消一个虚拟地址所在的页到物理页的映射。
注意点：
* 需要更新该页的pp_ref计数器
* 如果计数器减到零了，主动释放该物理页，这部分其实在`page_decref`中已经实现好了，直接调用就可以
* 如果PTE存在的话，将里面的内容清零
* TLB中如果有缓存该虚拟地址的映射，需要清除掉

#### page_insert()
这个函数和boot_map_region非常的类似，他们的区别如下：
1. boot_map_region只用来静态映射UTOP上面的一部分区域
2. page_insert函数如果发现该物理页已经映射到了别的虚拟页，必须清除掉原来的映射（别忘记TLB）
3. page_insert需要显式地增加pp_ref计数器

##**Part 3: Kernel Address Space**
### Exercise 5.
#### mem_init()
此时应该可以通过`check_page`的检查了，下面的任务是建立UTOP之上的地址空间，也就是内核所使用的地址空间部分。建议开始写之前仔细阅读`memlayout.h`中的注释，对整个虚拟地址空间有大致的了解。
```c
/*
 * Virtual memory map:                                Permissions
 *                                                    kernel/user
 *
 *    4 Gig -------->  +------------------------------+
 *                     |                              | RW/--
 *                     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *                     :              .               :
 *                     :              .               :
 *                     :              .               :
 *                     |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~| RW/--
 *                     |                              | RW/--
 *                     |   Remapped Physical Memory   | RW/--
 *                     |                              | RW/--
 *    KERNBASE ----->  +------------------------------+ 0xf0000000
 *                     |       Empty Memory (*)       | --/--  PTSIZE
 *    KSTACKTOP ---->  +------------------------------+ 0xefc00000      --+
 *                     |         Kernel Stack         | RW/--  KSTKSIZE   |
 *                     | - - - - - - - - - - - - - - -|                 PTSIZE
 *                     |      Invalid Memory (*)      | --/--             |
 *    ULIM     ------> +------------------------------+ 0xef800000      --+
 *                     |  Cur. Page Table (User R-)   | R-/R-  PTSIZE
 *    UVPT      ---->  +------------------------------+ 0xef400000
 *                     |          RO PAGES            | R-/R-  PTSIZE
 *    UPAGES    ---->  +------------------------------+ 0xef000000
 *                     |           RO ENVS            | R-/R-  PTSIZE
 * UTOP,UENVS ------>  +------------------------------+ 0xeec00000
 * UXSTACKTOP -/       |     User Exception Stack     | RW/RW  PGSIZE
 *                     +------------------------------+ 0xeebff000
 *                     |       Empty Memory (*)       | --/--  PGSIZE
 *    USTACKTOP  --->  +------------------------------+ 0xeebfe000
 *                     |      Normal User Stack       | RW/RW  PGSIZE
 *                     +------------------------------+ 0xeebfd000
 *                     |                              |
 *                     |                              |
 *                     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *                     .                              .
 *                     .                              .
 *                     .                              .
 *                     |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
 *                     |     Program Data & Heap      |
 *    UTEXT -------->  +------------------------------+ 0x00800000
 *    PFTEMP ------->  |       Empty Memory (*)       |        PTSIZE
 *                     |                              |
 *    UTEMP -------->  +------------------------------+ 0x00400000      --+
 *                     |       Empty Memory (*)       |                   |
 *                     | - - - - - - - - - - - - - - -|                   |
 *                     |  User STAB Data (optional)   |                 PTSIZE
 *    USTABDATA ---->  +------------------------------+ 0x00200000        |
 *                     |       Empty Memory (*)       |                   |
 *    0 ------------>  +------------------------------+                 --+
```

还需要了解PTE中的权限位，权限位的定义在`mmu.h`头文件中
```c
// Page table/directory entry flags.
#define PTE_P		0x001	// Present
#define PTE_W		0x002	// Writeable
#define PTE_U		0x004	// User
#define PTE_PWT		0x008	// Write-Through
#define PTE_PCD		0x010	// Cache-Disable
#define PTE_A		0x020	// Accessed
#define PTE_D		0x040	// Dirty
#define PTE_PS		0x080	// Page Size
#define PTE_G		0x100	// Global
```
现阶段需要使用的也就是P，W，U三种权限了。其中U代表允许User读该页，W代表允许User写该页。kernel对所有页有最高级别权限，不需要声明。
比如kernel R， user R 可以写成这样：
```c
perm = PTE_U | PTE_P
```

mem_init中剩余的代码都是在建立内核使用的虚拟地址空间，可以细分成为三个部分：
1. 将pages结构所在的物理内存映射到虚拟地址空间的UPAGES处
2. 给内核的栈所在的物理内存建立映射
3. 原来使用的页表不再使用了，在更换CR3之前，在新的页表中建立KERNBASE以上物理地址空间的映射

这些映射的建立都是固定的，不需要再改变，所以全部使用的是之前实现的`boot_map_region`函数。
其中1和3比较简单，略过不表。我们来看一下第二部分。
将物理地址bootstack映射到虚拟地址空间中正确的位置。这个bootstack又是一个在entry.S中定义的变量。
我们来看一下先。
```c
.data
###################################################################
# boot stack
###################################################################
	.p2align	PGSHIFT		# force page alignment
	.globl		bootstack
bootstack:
	.space		KSTKSIZE
	.globl		bootstacktop   
bootstacktop:
```
可以看到在bootstack和bootstacktop之间，预留了KSTKSIZE大小的空间给未来的内核栈。
这一部分是用汇编写的，我们注意到实在.data段内，所以在将kernel的ELF可执行文件加载到内存中的时候，
.data段也会被加载到内存中，并且给将来的内核栈预留好空间。
还有一个有意思的地方，就是在内核栈的下面有一段内存不被映射到任何一段物理内存，Kernel 栈在使用过程中会向下增长，如果遇到了出错的情况，
栈指针就会越过界限到达Invalid memory,此时由于这部分虚拟地址空间没有建立映射，会触发Page Fault，系统就会知道可能有错误放生了。
这个Invalid Memory的原理有点像“金丝雀”。
我们必须将Invalid memory对应的PTE清零：
```c
	uintptr_t gp = KSTACKTOP - PTSIZE;
	while(gp < KSTACKTOP - KSTKSIZE){
		pte_t * pte = pgdir_walk(kern_pgdir, (void*)gp, 0);
		if(pte != NULL){
			*pte = 0;
		}
		gp += PGSIZE;
	}
```
** Invalid Memory示意图**
```c
   KSTACKTOP ---->  +------------------------------+ 0xefc00000      --+
 *                     |         Kernel Stack         | RW/--  KSTKSIZE   |
 *                     | - - - - - - - - - - - - - - -|                 PTSIZE
 *                     |      Invalid Memory (*)      | --/--             |
 *    ULIM     ------> +------------------------------+ 0xef800000      --+
```

### Exercise 6.
为一部分物理页的映射开启大页表，节省overhead。这样做的原因是有些页不是经常在内存中换进换出，比如kernel所在的页。
方法在Intel文档中有介绍，就是调用rcr4()获得CR4寄存器的值， 打开CR4寄存器中的CR4_PSE位，再调用lcr4()命令更新CR4