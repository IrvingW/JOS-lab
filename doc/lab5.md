## JOS Lab5 File System
[TOC]
我们要实现的文件系统比较简单，因为JOS目前只支持一个用户，所以我们的文件系统也就不支持UNIX系统中的文件所有者和文件的权限等一些概念，并且目前也不支持hard links, symbolic links, time stamps或者是特殊的驱动文件．

我们将要实现的文件系统甚至不需要使用inode,而是简单地将文件以及子目录的元信息存储在目录中的唯一一个描述该文件的directory entry之中．而所有对于目录内容的修改都被封装在了文件的创建和删除操作中了．同时我们的文件系统允许用户态的程序可以读取目录中的元信息．虽然这样可以让我们在用户态就可以实现ls等操作，然而这样做的缺点在于他使得应用程序的实现依赖于目录中元信息的存储方式．使得修改存储方式变得困难．
我们的文件系统中的block size将使用4K大小，来和处理器的页大小匹配．
我们的文件系统将拥有一个super block，处于磁盘的第二个block（block 1）的位置．他的结构在inc/fs.h这个文件中有定义．而block 0用于存储存储boot loader程序和分区表，也就是说文件系统不使用磁盘上面的第一个block.

就在super block后面是一块用来跟踪记录磁盘上面的哪些block是free的bitmap,每32768个disk blocks（64MB）就需要使用一个block用来存储bitmap.在bitmap当中，1表示该block是空闲的，0表示该block被占用．

文件的元信息在inc/fs.h这个文件中有存储，文件的元信息中包括文件名，文件的类型，文件的大小，以及指向存储文件内容的block的指针．我们的文件系统不使用inode,所以这些信息都直接被存储在了目录文件里面的目录项中了．为了简单起见，无论是在磁盘上还是在内存中，我们都使用同一个`File`结构来表示文件元信息．
在File结构中，f_direct数组中存的是文件中头10个block的block的block number,对于小于40KB的文件，只使用这些直接block就够了．对于大一些的文件，文件系统会专门分配一个block来存储剩下的indirect block number．也就是说JOS文件系统中最大的文件可以拥有1034个block，刚刚超过4MB．

File结构既可以用来存储文件的元信息，也可以用来存储目录的元信息．两者的区别在于目录的block里面存储的是一条一条的下属目录/文件的元信息．

super block也存储有一个File结构(Super结构中的root字段)，里面存的是文件系统的根目录的元信息．

### Disk Access
不同于传统文件系统，我们不会在内核中实现一个拥有必要的系统调用的IDE硬盘驱动，我们会在用户态实现一个硬盘驱动，在用户态直接操作硬盘．
我们不会用中断的方式实现I/O,而是会采用低效但是容易实现的PIO方式来控制I/O.
x86处理器使用EFLAGS寄存器中的IOPL位来决定保护模式的代码是否被允许使用IN和OUT这种设备I/O指令．因为所有用来控制IDE硬盘的寄存器地址都被定位到I/O地址空间，只需要颁发给文件系统环境进程I/O权限，文件系统就可以访问这些寄存器了．而除了文件系统环境进程之外的其他环境进程，我们不希望他们拥有访问I/O地址空间的权限．

#### Exercise 1.
接下来我们就将要处理给文件系统环境进程颁发I/O优先级的代码．
这部分我们在创建新的环境进程的时候就完成了，当env_create发现要创建的进程的类型是文件系统进程，就会将该进程的EFLAGS寄存器中的IOPL位置上，这样文件系统进程就拥有了执行I/O指令的优先级．
代码如下：
```c
if(type == ENV_TYPE_FS){
    e->env_tf.tf_eflags |= FL_IOPL_MASK;
}
```

至于当环境进程切换的时候，这个优先级位就和EFLAGS寄存器一同被恢复了，借助Env结构中存储的该环境进程各个寄存器的值．

### The Block Cache
在虚拟地址空间的帮助下，我们的JOS文件系统要实现一个block cache.这部分代码在fs/bc.c之中．
由于虚拟地址空间大小的限制，我们的文件系统最多不能超过3GB.被映射到虚拟地址空间从`DISKMAP`开始的3GB空间范围之内．当然了，将整个磁盘上面的内容全部读到内存之中显然是不现实的，所以我们仍然利用page fault的方法动态的将需要用到的磁盘上面的block加载到内存中

#### Exercise 2.
实现fs/bc.c中的page fault 处理函数－－bc_pgfault，他的任务是在发生page_fault的时候从磁盘中将需要的block加载到内存中．需要注意两点：
1. addr 可能不是block size大小对齐的
2. ide_read是以sector为单位读取磁盘的，不是block

flush_block函数的功能是将内存中缓存的block写回到磁盘上去．如果block根本就不在内存中或者和磁盘中的没什么两样的话什么都不用做．我们将利用页表项上面的dirty位来记录自从上一次从磁盘中读出一块block或者写回磁盘一块block之后有没有修改过内存中的这块block．处理器的硬件特性是如果去写一个页那么他的页表项的dirty位就会被设置上．
在将内存中的block　flush到磁盘上之后，需要利用sys_page_map函数将dirty位清掉．

### The Block Bitmap
#### Exercise 3.
利用bitmap我们可以轻易的找到磁盘上空闲的block，于是这个练习我们要实现的alloc_block也使用这种方法．注意分配了一个block之后，立刻需要将修改过的bitmap刷回磁盘，以保证一致性．

### File Operations
#### Exercise 4.

### Client/Server File System Access
目前为止我们已经实现了文件系统需要的大部分操作，虽然绝大部分都是已经给出的代码．．．．
下面我们就要给其他进程提供访问文件系统的接口了．
JOS文件系统通过进程间通信的方式远程调用文件系统环境进程这边的具体执行操作的函数方法．还记得上一个lab我们实现的IPC机制嘛，我们通过共享页面的方式来进行进程之间通信．而这一次的远程方法调用RPC就是基于IPC来实现的．
整个流程如图所示：
```c
      Regular env           FS env
   +---------------+   +---------------+
   |      read     |   |   file_read   |
   |   (lib/fd.c)  |   |   (fs/fs.c)   |
...|.......|.......|...|.......^.......|...............
   |       v       |   |       |       | RPC mechanism
   |  devfile_read |   |  serve_read   |
   |  (lib/file.c) |   |  (fs/serv.c)  |
   |       |       |   |       ^       |
   |       v       |   |       |       |
   |     fsipc     |   |     serve     |
   |  (lib/file.c) |   |  (fs/serv.c)  |
   |       |       |   |       ^       |
   |       v       |   |       |       |
   |   ipc_send    |   |   ipc_recv    |
   |       |       |   |       ^       |
   +-------|-------+   +-------|-------+
           |                   |
           +-------------------+
```
需要留意的是client端使用ipc_recv接受调用返回的时候不需要再给一个新的页面，如果需要共享页面的话server端会直接写在原来传过去的那个页里面．
那么，文件系统环境进程是怎么找到某一个特定的打开文件的呢．
在server端，每一个打开的文件有三个结构和他绑定，分别是：
1. `struct File` 这部分本来是在磁盘上的，被映射到内存中．这部分内容只有文件系统环境进程可以看到．
2. `struct Fd`　每一个打开的文件才有，和Unix文件系统中的file descriptor很类似．存储在内存中．每一个Fd结构都会占据一整个页，server端通过不同页(物理页)上面的pp_ref字段来表示这个文件被多少个环境共享．当pp_ref为１时，说明这个文件在所有的进程中都被关闭了．
3. `struct OpenFile`　连接着上面的两种结构，并且只有文件系统环境进程可见．文件系统server端维护着一个所有打开文件的数组结构，以File Id作为索引．使用openfile_lookup可以将file Id翻译成为OpenFile 结构．


### Client-Side File Operations
lib/file.c中的实现都是针对磁盘上面的文件的操作．而在后续的lab里，我们还会实现很多设备，比如pipes,console I/O等等，每中设备最后都会实现类似的read/write接口供用户使用．在Fd结构中就记录该文件属于什么设备，在lib/fd.c中，根据Dev的不同，操作被分发到不同的操作实现上面去．
在每个应用环境进程的地址空间中有一块用于放置文件描述符表，在FSTABLE开始处的4KB空间内，存储了该进程最多可以打开的32个文件的文件描述符．每个文件描述符在FILEDATA处还可以选择

#### Exercise 7
这个练习我们实现file.ｃ文件中的open函数．
首先在进程的FDTABLE中找到一个没有被使用的Fd结构，这里使用的fd_alloc并不会真正的帮我们分配一个Fd出来，而是返回我们空着的Fd，由caller负责真正去申请Fd.通过IPC调用文件系统服务进程打开一个文件．注意在打开文件的个数已经达到了最大可打开文件个数，或者IPC过程遇到错误时退出，不继续执行．

### Spawning Processes
其实从文件系统中加载镜像创建新的环境进程的代码已经给好了．spawn函数的作用就好象是UNIX系统中的fork然后紧跟着一条exec操作.
在lib/spawn.c文件中有spawn实现的完整代码，我们可以先来看一看spawn是怎样实现的．
首先在user/icode.c中我们可以看到真正被调用的不是spawn函数而是他的包装函数spawnl(),包装函数主要就是将参数封装到一个数组中用来调用spawn().参数被封装到一个argv数组中，大小是argc+1，因为末尾是一个空指针用来标识结尾．spawn函数内部的实现就是首先fork出一个子进程，然后将他的trapframe以及stack都设置好，然后将ELF可执行文件中的每个段加载到子进程内存空间中的相应位置上，最后将状态设置为RUNNABLE就可以了．
在加载各个段的过程中，利用了父进程内存空间中UTMP处的一页大小内存作为中转站，先将文件中的内容读取到UTMP位置，再将该位置映射的物理页映射到子进程的虚拟地址空间中正确位置上面．
初始化子进程的栈的时候，要做的是将参数存储到新进程的栈上面．首先将存储的结构先在UTMP上一个页大小的空间中构造好再重新映射到正确的位置（USTACKTOP的正下方）．
参数全部以字符串的形式存在一起（string_store）,指向参数字符串开始位置的指针存储在argv_store中．argv_store结构的下方栈上压入了两个值，一个记录参数的数量，一个记录参数数组在栈上面开始的位置．在这下面就是我们`%esp`初始的位置了．也就是说，栈第一个调用的函数是:
```c
entry(argc, argv);
```


#### Exercise 8.
spawn依赖于新的系统调用：sys_env_set_trapframe在初始化新的环境的时候建立环境的trapframe．在系统掉用中，我们设置的trapframe会在退出内核态的时候被恢复到进程的各个寄存器中，所以我们设置的trapframe应该是用户态的．也就是说需要打开中断和CIP=3.


### Challenge
我选择的是实现UNIX上的exec函数．
我的思路是前半部分照抄spawn，也就是fork出一个新的子进程然后将ELF文件加载到这个进程的地址空间中然后设置第一个栈．
之后调用一个系统调用进入内核态，将当前进程的页表和trapframe全部替换成子进程的．这样就可以一次性改掉当前进程内存空间中的
内容了．
实现的系统调用如下
```c
static int
sys_env_exchange(envid_t envid){
	int r;
	struct Env *e;
  struct Trapframe tmp_tf;
  pte_t * tmp_pgdir;

	if ((r = envid2env(envid, &e, 1)) < 0)
		return r;

  tmp_tf = e->env_tf;
  e->env_tf = curenv->env_tf;
  curenv->env_tf = tmp_tf;

  tmp_pgdir = e->env_pgdir;
  e->env_pgdir = curenv->env_pgdir;
  curenv->env_pgdir = tmp_pgdir;

	env_destroy(e);
  lcr3(PADDR(curenv->env_pgdir));
  unlock_kernel();
  env_pop_tf(&curenv->env_tf);
	return 0; // never return 
}
```
最后实现的效果如下，可以看到在原来的进程中加载了inic程序，然后inode.c最后的existing并没有打印，说明原来的程序流直接改变了

icode: close /motd
icode: spawn /init
init: running
init: data seems okay
init: bss seems okay
init: args: 'init' 'initarg1' 'initarg2'
init: exiting
[00001009] exiting gracefully
No more runnable environments!

如果想看运行效果的话我写了一个测试用例user/icodeExec.c
可以运行　make run-icodeExec　查看效果．