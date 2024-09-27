+++
title = 'Linux下的进程与线程'
date = 2024-09-26T21:38:22+08:00
draft = false
tags = ["线程", "进程", "Linux"]
+++

### 一、从一段简单的代码开始

```c
#include <unistd.h>
#include <pthread.h>

void *
hello_thread() { }
 
int
main() {
    pthread_t tid;
    pid_t pid = fork();
    if (pid) {
        pthread_create(&tid, NULL, hello_thread, NULL);
        pthread_join(tid, NULL);
    }
}
```
我们用`strace`命令跟踪一下这段代码的执行
```shell
......
clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fc07fca0a10) = 7206
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=7206, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---
......
clone(child_stack=0x7fc07fc8ffb0, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, parent_tid=[0], tls=0x7fc07fc90700, child_tidptr=0x7fc07fc909d0) = 7207
exit_group(0)                           = ?
+++ exited with 0 +++
```

可以看到，不管是创建`fork()`还是`pthread_create()`，都是通过`clone()`这个系统调用来实现的，但是两者传入的参数，特别是在*flags*上又有着不小的差异。

那么`clone()`到底做了什么呢？

通过检查系统调用表[syscall_64.tbl](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/entry/syscalls/syscall_64.tbl)，可以发现`clone()`系统调用由`sys_clone()`函数处理。

再在[fork.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/fork.c)文件中找到`sys_clone()`函数定义
```c
SYSCALL_DEFINE6(clone, unsigned long, clone_flags, unsigned long, newsp,
		int, stack_size,
		int __user *, parent_tidptr,
		int __user *, child_tidptr,
		unsigned long, tls)
{
	struct kernel_clone_args args = {
		.flags		= (lower_32_bits(clone_flags) & ~CSIGNAL),
		.pidfd		= parent_tidptr,
		.child_tid	= child_tidptr,
		.parent_tid	= parent_tidptr,
		.exit_signal	= (lower_32_bits(clone_flags) & CSIGNAL),
		.stack		= newsp,
		.tls		= tls,
	};

	return kernel_clone(&args);
}
```

这个由`SYSCALL_DEFINE6`宏定义的`sys_clone()`函数转头调用了`kernel_clone()`，`kernel_clone()`函数又调用了`copy_process()`。来关注一下它的注释部分。
```c
/*
 * This creates a new process as a copy of the old one,
 * but does not actually start it yet.
 *
 * It copies the registers, and all the appropriate
 * parts of the process environment (as per the clone
 * flags). The actual kick-off is left to the caller.
 */
__latent_entropy struct task_struct *copy_process(
```

嗯，看来`copy_process()`的主要工作是从旧的*process*中复制一个新的出来，可以注意到它返回一个`task_struct *`类型的指针。

这个`task_struct`是干什么用的？再回到`kernel_clone()`函数。

```c
/*
 *  Ok, this is the main fork-routine.
 *
 * It copies the process, and if successful kick-starts
 * it and waits for it to finish using the VM if required.
 *
 * args->exit_signal is expected to be checked for sanity by the caller.
 */
pid_t kernel_clone(struct kernel_clone_args *args)
{
	u64 clone_flags = args->flags;
	struct completion vfork;
	struct pid *pid;
	struct task_struct *p;
	...
	p = copy_process(NULL, trace, NUMA_NO_NODE, args);
	...
	wake_up_new_task(p);
	...
}
```

在复制完*process*以后，用得到的`task_struct`指针调用了一个名为`wake_up_new_task()`的函数。从名字可以看出，这个函数的作用，应该是唤醒这个复制出来的东西。

在[core.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/sched/core.c)中继续跟踪`wake_up_new_task()`函数。

```c
/*
 * wake_up_new_task - wake up a newly created task for the first time.
 *
 * This function will do some initial scheduler statistics housekeeping
 * that must be done for every newly created context, then puts the task
 * on the runqueue and wakes it.
 */
void wake_up_new_task(struct task_struct *p)
{
	struct rq_flags rf;
	struct rq *rq;

	raw_spin_lock_irqsave(&p->pi_lock, rf.flags);
	WRITE_ONCE(p->__state, TASK_RUNNING);
	...
	post_init_entity_util_avg(p);

	activate_task(rq, p, ENQUEUE_NOCLOCK | ENQUEUE_INITIAL);
	trace_sched_wakeup_new(p);
	wakeup_preempt(rq, p, WF_FORK);
	...
}
```

果然跟猜的差不多，这里做一些初始化操作，之后把复制得到的`task_struct`结构体放到一个叫`runqueue`的东西上，然后唤醒它。

### 二、内核调度实体(KSE, Kernel Scheduling Entity)

在继续之前，我们需要引入一个概念，叫内核调度实体。

现代操作系统中通常会同时执行许多任务，哪怕它运行在拥有集成度非常高的多核CPU之上，也不足以让每一个任务都独占一个核心。因此，Linux内核实现了多种调度算法，能够从许多等待执行的任务中挑选一个出来，*恢复任务的执行环境*，然后将它交给CPU的核心来运行。

这些等待被内核选中交给CPU运行的任务，就叫做内核调度实体。

这些任务也就是上面`copy_process()`所创建的`task_struct`，由`runqueue`维护，它是一个`struct rq *`类型的指针，每个cpu都有自己的`runqueue`。

也就是说，线程与进程并无区别，都是内核调度实体？

### 三、资源共享

再回到`copy_process()`函数，可以看到这里有针对参数*flags*的处理，而*flags*是`fork()`与`pthread_create()`两个方法调用`clone()`时最大的不同点。
```c
......
const u64 clone_flags = args->flags;
......
retval = copy_semundo(clone_flags, p);
if (retval)
    goto bad_fork_cleanup_security;
retval = copy_files(clone_flags, p, args->no_files);
if (retval)
    goto bad_fork_cleanup_semundo;
retval = copy_fs(clone_flags, p);
if (retval)
    goto bad_fork_cleanup_files;
retval = copy_sighand(clone_flags, p);
if (retval)
    goto bad_fork_cleanup_fs;
retval = copy_signal(clone_flags, p);
if (retval)
    goto bad_fork_cleanup_sighand;
retval = copy_mm(clone_flags, p);
if (retval)
    goto bad_fork_cleanup_signal;
retval = copy_namespaces(clone_flags, p);
if (retval)
    goto bad_fork_cleanup_mm;
retval = copy_io(clone_flags, p);
if (retval)
    goto bad_fork_cleanup_namespaces;
retval = copy_thread(p, args);
......
```

看来关键点在这里了。我们选择一个简单的`copy_files`函数跟踪，看看不同*flag*会有什么不同的处理
```c
static int copy_files(unsigned long clone_flags, struct task_struct *tsk,
		      int no_files)
{
	struct files_struct *oldf, *newf;
	int error = 0;

	/*
	 * A background process may not have any files ...
	 */
	oldf = current->files;
	if (!oldf)
		goto out;

	if (no_files) {
		tsk->files = NULL;
		goto out;
	}

	if (clone_flags & CLONE_FILES) {
		atomic_inc(&oldf->count);
		goto out;
	}

	newf = dup_fd(oldf, NR_OPEN_MAX, &error);
	if (!newf)
		goto out;

	tsk->files = newf;
	error = 0;
out:
	return error;
}
```

方法很简单，可以看到，如果调用`clone()`时指定了`CLONE_FILES`，在执行`copy_files`时，就只是简单地将`files->count`加1，然后返回。如果未指定`CLONE_FILES`，则需要调用`dup_fd()`复制文件描述符，并将复制出来的文件描述符赋值给新创建的`task_struct`。

显然，如果文件描述符被复制，在新的`task_struct`运行时关闭此前打开的文件描述符，**并不影响**原来的`task_struct`，其他如`fs`、`namespace`、`mm`等资源也同理。

这也就是说，如果是采用的`fork()`创建的`task_struct`，大部分资源与原`task_struct`隔离开的，互不影响。而`pthread_create()`创建的`task_struct`则采用了资源共享的方式。

所以，Linux内核里并没有线程与进程的概念，统一都叫做`task`。

### 四、线程模型

不过，我们在讨论*线程*的时候，真的是在说`task_struct`吗？

线程可以分为用户态线程和内核态线程。`pthread`是一个用户态线程库标准，全称是`POSIX thread`。而`NPTL`是它在Linux平台实现的一个库函数，全称为`Native POSIX Thread Library`。

而显然，`task_struct`是一个内核态的“线程”。为何我们调用`pthread_create()`会为我们复制一个内核态的“线程”呢？

这是因为`NPTL`采用了1:1的线程模型。也就是说，我们在用户态创建的每一个线程，在内核都有一个对应的可调度实体。

因此在Linux下，线程的切换分为两类：一类是线程间的切换，称为`context switch`；另一类是同一线程在用户态与内核态之间的切换，称为`mode switch`。

当我们需要从一个线程A切换到另一个线程B时，首先A会从用户态进入到内核态，然后在内核里从线程A切换到线程B，最后从线程B的内核态切换到线程B的用户态，开始执行用户态代码。

### 五、结论

就不总结啦🤭