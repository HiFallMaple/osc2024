#include "sched.h"
#include "memory.h"
#include "timer.h"
#include "list.h"
#include "stddef.h"
#include "string.h"
#include "syscall.h"
#include "exception.h"
#include "callback_adapter.h"
#include "uart1.h"

struct list_head *run_queue;

thread_t *threads[MAX_PID + 1];
thread_t *curr_thread;
extern char _start;
extern char _end;

static int64_t pid_history = 0;
int8_t need_to_schedule = 0;

// void _SIGNAL_COPY(thread_t *dest_thread, thread_t *src_thread)
// {
// 	dest_thread->signal = src_thread->signal;
// 	dest_thread->signal.pending_list = kmalloc(sizeof(signal_node_t));
// 	INIT_LIST_HEAD((list_head_t *)dest_thread->signal.pending_list);
// 	list_head_t *curr;
// 	list_for_each(curr, (list_head_t *)src_thread->signal.pending_list)
// 	{
// 		signal_node_t *new_node = kmalloc(sizeof(signal_node_t));
// 		new_node->signal = ((signal_node_t *)curr)->signal;
// 		list_add_tail((list_head_t *)new_node, (list_head_t *)dest_thread->signal.pending_list);
// 	}
// }

static inline int8_t in_kernel_img_space(uint64_t addr)
{
	DEBUG("addr: 0x%x, _start: 0x%x, _end: 0x%x\n", addr, &_start, &_end);
	return addr >= &_start && addr < &_end;
}

static inline thread_t *child_node_to_thread(child_node_t *node)
{
	return threads[(node)->pid];
}

static inline int free_child_thread(thread_t *child_thread)
{
	list_head_t *curr;
	list_head_t *n;
	list_for_each_safe(curr, n, (list_head_t *)child_thread->child_list)
	{
		thread_t *curr_child = child_node_to_thread((child_node_t *)curr);
		curr_child->ppid = 1; // assign to init process
		list_del_entry(curr);
		list_add_tail(curr, (list_head_t *)threads[1]->child_list);
	}

	if (thread_code_can_free(child_thread))
	{
		kfree(child_thread->code);
	}
	threads[child_thread->pid] = NULL;
	kfree(child_thread->child_list);
	kfree(child_thread->user_stack_base);
	kfree(child_thread->kernel_stack_base);
	kfree(child_thread->name);
	kfree(child_thread);
	return 0;
}

inline int8_t thread_code_can_free(thread_t *thread)
{
	return !in_kernel_img_space((uint64_t)thread->code);
}

void init_thread_sched()
{
	kernel_lock_interrupt();
	run_queue = kmalloc(sizeof(thread_t));
	INIT_LIST_HEAD(run_queue);

	char *thread_name = kmalloc(5);
	strcpy(thread_name, "idle");
	_init_create_thread(thread_name, 0, 0, idle);
	set_current_thread_context(&(threads[0]->context));
	thread_name = kmalloc(5);
	strcpy(thread_name, "init");
	curr_thread = thread_create(init, thread_name);
	curr_thread->code = init;
	curr_thread->datasize = 4000;
	kernel_unlock_interrupt();
}

void _init_create_thread(char *name, int64_t pid, int64_t ppid, void *start)
{
	thread_t *thread = (thread_t *)kmalloc(sizeof(thread_t));
	init_thread_signal(thread);
	curr_thread = thread;
	threads[0] = thread;
	thread->name = name;
	thread->pid = pid;
	thread->ppid = ppid;
	thread->child_list = (child_node_t *)kmalloc(sizeof(child_node_t));
	INIT_LIST_HEAD((list_head_t *)thread->child_list);
	thread->status = THREAD_READY;
	thread->user_stack_base = kmalloc(USTACK_SIZE);
	thread->kernel_stack_base = kmalloc(KSTACK_SIZE);
	thread->context.lr = (uint64_t)start;
	thread->context.sp = (uint64_t)thread->kernel_stack_base + KSTACK_SIZE;
	thread->context.fp = thread->context.sp; // frame pointer for local variable, which is also in stack.
	list_add((list_head_t *)thread, run_queue);
}

void idle()
{
	DEBUG("idle process\r\n");
	while (1)
	{
		// wait();
		schedule();
	}
}

void init()
{
	while (1)
	{
		wait();
	}
}

void __init()
{
	DEBUG("user space init process\n");
	while (1)
	{
		DEBUG("wait\n");
		int c_pid = wait();
		DEBUG("child process %d exit\n", c_pid);
	}
}

int64_t wait()
{
	kernel_lock_interrupt();
	DEBUG("block thread: %d\n", curr_thread->pid);
	curr_thread->status = THREAD_BLOCKED;
	while (1)
	{
		// DEBUG("wait thread: %d\n", curr_thread->pid);
		kernel_unlock_interrupt();
		schedule();
		kernel_lock_interrupt();
		// DEBUG_BLOCK({
		// 	dump_child_thread(curr_thread);
		// });
		struct list_head *curr_child_node;
		list_head_t *n;
		list_for_each_safe(curr_child_node, n, (list_head_t *)curr_thread->child_list)
		{
			thread_t *child_thread = child_node_to_thread((child_node_t *)curr_child_node);
			if (child_thread->status == THREAD_ZOMBIE)
			{
				int64_t pid = child_thread->pid;
				DEBUG("wait thread kfree\n");
				free_child_thread(child_thread);
				list_del_entry(curr_child_node);
				kernel_unlock_interrupt();
				return pid;
			}
		}
	}
	kernel_unlock_interrupt();
	return 0;
}

void thread_exit()
{
	// thread cannot deallocate the stack while still using it, wait for someone to recycle it.
	// In this lab, idle thread handles this task, instead of parent thread.
	kernel_lock_interrupt();
	DEBUG("thread %d exit\n", curr_thread->pid);
	curr_thread->status = THREAD_ZOMBIE;
	list_del_entry((list_head_t *)curr_thread); // remove from run queue, still in parent's child list
	kernel_unlock_interrupt();
	schedule();
}

void thread_exit_by_pid(int64_t pid)
{
	// thread cannot deallocate the stack while still using it, wait for someone to recycle it.
	// In this lab, idle thread handles this task, instead of parent thread.
	kernel_lock_interrupt();
	DEBUG("thread %d exit\n", pid);
	thread_t *t = threads[pid];
	t->status = THREAD_ZOMBIE;
	list_del_entry((list_head_t *)t); // remove from run queue, still in parent's child list
	kernel_unlock_interrupt();
}

void schedule_timer()
{
	uint64_t cntfrq_el0;
	__asm__ __volatile__("mrs %0, cntfrq_el0\n\t" : "=r"(cntfrq_el0));
	// 32 * default timer -> trigger next schedule timer
	add_timer_by_tick(cntfrq_el0 >> 5, adapter_schedule_timer, NULL);
	need_to_schedule = 1;
}

thread_t *thread_create(void *start, char *name)
{
	kernel_lock_interrupt();
	thread_t *r;
	int64_t new_pid = -1;
	// find usable PID, don't use the previous one
	for (int i = 1; i < MAX_PID; i++)
	{
		if (threads[pid_history + i] == NULL)
		{
			new_pid = pid_history + i;
			break;
		}
	}
	if (new_pid == -1)
	{ // no available pid
		ERROR("no available pid, fork error\n");
		kernel_unlock_interrupt();
		return NULL;
	}
	else
	{
		pid_history = new_pid;
	}
	r = (thread_t *)kmalloc(sizeof(thread_t));
	DEBUG("new_pid: %d, thread address: 0x%x\n", new_pid, r);
	init_thread_signal(r);
	threads[new_pid] = r;
	r->name = name;
	r->pid = new_pid;
	r->ppid = curr_thread->pid;
	r->child_list = (child_node_t *)kmalloc(sizeof(child_node_t));
	INIT_LIST_HEAD((list_head_t *)r->child_list);
	r->status = THREAD_READY;
	r->user_stack_base = kmalloc(USTACK_SIZE);
	DEBUG("new_pid: %d, user_stack_base: 0x%x\n", new_pid, r->user_stack_base);
	r->kernel_stack_base = kmalloc(KSTACK_SIZE);
	DEBUG("new_pid: %d, kernel_stack_base: 0x%x\n", new_pid, r->kernel_stack_base);
	r->code = start;
	r->context.lr = (uint64_t)start;
	r->context.sp = (uint64_t)r->kernel_stack_base + KSTACK_SIZE;
	DEBUG("new_pid: %d, context.sp: 0x%x\n", new_pid, r->context.sp);
	r->context.fp = r->context.sp; // frame pointer for local variable, which is also in stack.

	child_node_t *child = (child_node_t *)kmalloc(sizeof(child_node_t));
	child->pid = new_pid;
	list_add_tail((list_head_t *)child, (list_head_t *)curr_thread->child_list);

	DEBUG("add new thread: %d, run_que: 0x%x\n", r->pid, run_queue);
	list_add((list_head_t *)r, run_queue);

	DEBUG("add new thread: %d\n", r->pid);
	kernel_unlock_interrupt();
	return r;
}

int8_t has_child(thread_t *thread)
{
	return !list_empty((list_head_t *)thread->child_list);
}

void schedule()
{
	kernel_lock_interrupt();
	thread_t *prev_thread = curr_thread;
	do
	{
		curr_thread = (thread_t *)(((list_head_t *)curr_thread)->next);
	} while (list_is_head((list_head_t *)curr_thread, run_queue)); // find a runnable thread
	// DEBUG("%d -> %d\n", prev_thread->pid, curr_thread->pid);
	curr_thread->status = THREAD_RUNNING;
	kernel_unlock_interrupt();
	switch_to(get_current_thread_context(), &(curr_thread->context));
}

void foo()
{
	// Lab5 Basic 1 Test function
	for (int i = 0; i < 10; ++i)
	{
		uart_puts("Thread id: %d %d\n", curr_thread->pid, i);
#ifdef QEMU
		for (int i = 0; i < 10000000; i++) // qemu
#else
		for (int i = 0; i < 100000; i++) // pi
#endif
		{
			asm volatile("nop");
		}
	}
	INFO("%s exit\n", curr_thread->name);
	thread_exit();
}

void dump_run_queue()
{
	recursion_run_queue(threads[1], 0);
}

void recursion_run_queue(thread_t *root, int64_t level)
{
	for (int i = 0; i < level; i++)
		printf("   ");
	printf(" |---");
	dump_thread_info(root);
	list_head_t *curr;
	list_for_each(curr, (list_head_t *)root->child_list)
	{
		// INFO("child: %d\n", child_node_to_thread((child_node_t *)curr)->pid);
		recursion_run_queue(child_node_to_thread((child_node_t *)curr), level + 1);
		// ERROR("OVER");
	}
	// uart_puts("---------------------- run queue list for each ----------------------\r\n");
	// list_for_each(curr, (list_head_t *)run_queue)
	// {
	// 	uart_puts("thread: 0x%x, thread->next: 0x%x, thread->prev: 0x%x, thread->name: %s, thread->pid: %d, thread->ppid: %d", curr, curr->next, curr->prev, ((thread_t *)curr)->name, ((thread_t *)curr)->pid, ((thread_t *)curr)->ppid);
	// 	switch (((thread_t *)curr)->status)
	// 	{
	// 	case THREAD_RUNNING:
	// 		uart_puts(", thread->status: THREAD_RUNNING\r\n");
	// 		break;
	// 	case THREAD_READY:
	// 		uart_puts(", thread->status: THREAD_READY\r\n");
	// 		break;
	// 	case THREAD_BLOCKED:
	// 		uart_puts(", thread->status: THREAD_BLOCKED\r\n");
	// 		break;
	// 	case THREAD_ZOMBIE:
	// 		uart_puts(", thread->status: THREAD_ZOMBIE\r\n");
	// 		break;
	// 	}
	// }
	// uart_puts("--------------------------------- end -------------------------------\r\n");
}

void dump_thread_info(thread_t *thread)
{
	printf("%s\t%d\t%d\t", thread->name, thread->pid, thread->ppid);
	switch (thread->status)
	{
	case THREAD_RUNNING:
		printf("RUNNING\r\n");
		break;
	case THREAD_READY:
		printf("READY\r\n");
		break;
	case THREAD_BLOCKED:
		printf("BLOCKED\r\n");
		break;
	case THREAD_ZOMBIE:
		printf("ZOMBIE\r\n");
		break;
	}
}

void dump_child_thread(thread_t *thread)
{
	list_head_t *curr;
	uart_puts("---------------------- child list for each ----------------------\r\n");
	list_for_each(curr, (list_head_t *)thread->child_list)
	{
		list_head_t *curr_child = (list_head_t *)threads[((child_node_t *)curr)->pid];

		uart_puts("thread: 0x%x, thread->next: 0x%x, thread->prev: 0x%x, thread->name: %s, thread->pid: %d, thread->ppid: %d", curr_child, curr_child->next, curr_child->prev, ((thread_t *)curr_child)->name, ((thread_t *)curr_child)->pid, ((thread_t *)curr_child)->ppid);
		switch (((thread_t *)curr_child)->status)
		{
		case THREAD_RUNNING:
			uart_puts(", thread->status: THREAD_RUNNING\r\n");
			break;
		case THREAD_READY:
			uart_puts(", thread->status: THREAD_READY\r\n");
			break;
		case THREAD_BLOCKED:
			uart_puts(", thread->status: THREAD_BLOCKED\r\n");
			break;
		case THREAD_ZOMBIE:
			uart_puts(", thread->status: THREAD_ZOMBIE\r\n");
			break;
		}
	}
	uart_puts("----------------------------- end ------------------------------\r\n");
}