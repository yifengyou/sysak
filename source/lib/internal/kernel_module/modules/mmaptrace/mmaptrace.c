#include <linux/file.h>
#include <linux/pid_namespace.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/stacktrace.h>
#include <linux/hrtimer.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/timex.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/sysctl.h>
#include <linux/rtc.h>
#include <linux/time.h>
#include <linux/version.h>
#include <linux/tracepoint.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/bug.h>
#include "common/proc.h"

#ifdef CONFIG_X86
extern struct mm_struct *get_task_mm(struct task_struct *task);

#define DEFINE_PROC_ATTRIBUTE(name, __write)				\
	static int name##_open(struct inode *inode, struct file *file)	\
	{								\
		return single_open(file, name##_show, PDE_DATA(inode));	\
	}								\
									\
	static const struct file_operations name##_fops = {		\
		.owner		= THIS_MODULE,				\
		.open		= name##_open,				\
		.read		= seq_read,				\
		.write		= __write,				\
		.llseek		= seq_lseek,				\
		.release	= single_release,			\
	}

#define DEFINE_PROC_ATTRIBUTE_RW(name)					\
	static ssize_t name##_write(struct file *file,			\
				    const char __user *buf,		\
				    size_t count, loff_t *ppos)		\
	{								\
		return name##_store(PDE_DATA(file_inode(file)), buf,	\
				    count);				\
	}								\
	DEFINE_PROC_ATTRIBUTE(name, name##_write)

#define DEFINE_PROC_ATTRIBUTE_RO(name)	\
	DEFINE_PROC_ATTRIBUTE(name, NULL)


#define MAX_SYMBOL_LEN	64
#define PATH_LEN 256
#define STACK_DEPTH 100
#define STACK_DETAIL_DEPTH 20
#define PERTASK_STACK 10
#define LIST_LEN 10
#define PROC_NUMBUF 128
#define REGISTER_FAILED 1

static bool enable_mmaptrace = false;
static unsigned long mmap_len = 246 << 10;
static pid_t mmap_pid;
static int brk;

LIST_HEAD(threads_list);
LIST_HEAD(threadvma_list);

DECLARE_RWSEM(threadslist_sem);
DECLARE_RWSEM(vmalist_sem);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
static struct kprobe kp_mmap = {
	.symbol_name	= "ksys_mmap_pgoff",
};

static struct kprobe kp_brk = {
	.symbol_name	= "do_brk_flags",
};
#else
static struct kprobe kp_mmap = {
	.symbol_name	= "vm_mmap_pgoff",
};

static struct kprobe kp_brk = {
	.symbol_name	= "do_brk",
};
#endif

struct stack_info {
	unsigned long bp;
	char path[PATH_LEN];
};

struct user_stack_detail {
	struct list_head list;
	int is_brk;
#if defined(DIAG_ARM64)
	//struct user_pt_regs regs;
#else
	//struct pt_regs regs;
#endif
	//unsigned long ip;
	//unsigned long bp;
	//unsigned long sp;
	struct stack_info stack[STACK_DETAIL_DEPTH];
};

struct task_info{
	pid_t pid;
	pid_t tgid;
	struct list_head task_list;	
    unsigned long mmap_count;
	struct list_head vma_list;	
	unsigned long userstack_list_len;
	struct list_head userstack_list;
	char comm[TASK_COMM_LEN];
};

struct vma_info{
	struct list_head list;
	pid_t pid;
	unsigned long start;
	unsigned long end;
	int exectue;
	char path[PATH_LEN];
};

struct stack_frame_user {
	const void __user *next_fp;
	unsigned long ret_addr;
};


static void save_mmapstack_trace_user(struct task_struct *task, struct task_info *tsk)
{
	struct list_head *vma_entry;
	const struct pt_regs *regs = task_pt_regs(current);
	const void __user *fp = (const void __user *)regs->sp;
	int stack_len = 0 ;
	int i;

	struct user_stack_detail *new_stack = kzalloc(sizeof(struct user_stack_detail),GFP_KERNEL);
	if (!new_stack)
		return;
	new_stack->is_brk = brk;
	for (i = 0; i < STACK_DEPTH; i++){
		if (stack_len > STACK_DETAIL_DEPTH)
			break;
		list_for_each(vma_entry, &threadvma_list){	
			//struct vma_info *vma = (struct vma_info *)vma_entry;
			struct vma_info *vma = container_of(vma_entry, struct vma_info, list);
			unsigned long tmp;

			if (!copy_from_user(&tmp, fp+i*__SIZEOF_LONG__, __SIZEOF_LONG__)) {
				if ((tmp >= vma->start) && (tmp <= vma->end)) {
					new_stack->stack[stack_len].bp = tmp;
					strcpy(new_stack->stack[stack_len].path,vma->path);
					stack_len++;
				}
			}
		}
	}
	list_add_tail(&new_stack->list, &tsk->userstack_list);				
}

static int save_calltrace(struct pt_regs *regs)
{
	struct list_head *tsk_entry;
	struct task_info *new_tsk;
	pid_t tgid = 0;

	//down_write(&threadslist_sem);
	list_for_each(tsk_entry, &threads_list){
		struct task_info *tsk = container_of(tsk_entry, struct task_info, task_list);
		tgid = tsk->tgid;
		if (tsk->pid == current->pid){
			if (tsk->userstack_list_len > LIST_LEN){
				return 0;
			}
			save_mmapstack_trace_user(current,tsk);
			return 0;
		}	
        //save stack
    }
	if (tgid == current->tgid){
		new_tsk = kzalloc(sizeof(struct task_info),GFP_KERNEL);
		if (!new_tsk)
			return 0;
	    new_tsk->pid = current->pid;
        new_tsk->tgid = tgid;
	    memcpy(new_tsk->comm,current->comm,sizeof(new_tsk->comm));
	    new_tsk->mmap_count++;
		INIT_LIST_HEAD(&new_tsk->userstack_list);
		save_mmapstack_trace_user(current,new_tsk);
		list_add_tail(&new_tsk->task_list,&threads_list);
	}
	//up_write(&threadslist_sem);
	return 0;
}

static int before_mmap_pgoff(struct kprobe *p, struct pt_regs *regs)
{
	int ret;

	brk = 0;
	if (regs->si < mmap_len){
		return 0;
	}
	if (!current || !current->mm)
		return 0;

	ret = save_calltrace(regs);
    return 0;
}

static void after_mmap_pgoff(struct kprobe *p, struct pt_regs *regs,
                unsigned long flags)
{
	return;
}

static void get_filename(char *buf, const struct path *path, size_t size)
{
	//int res = -1;
	//char *end;
	if (size) {
		char *p = d_path(path, buf, size);
		if (!IS_ERR(p)) {
			strcpy(buf,p);
			//end = mangle_path(buf, p, "\n");
			//if (end)
				//res = end - buf;
		}
	}
	return;
}

static int mmaptrace_print_show(struct seq_file *m, void *v)
{
	struct list_head *tsk_entry;
	struct list_head *stack_entry;
	int loop_count = 0;
	char *syscall_name;
	int i;

	//down_read(&threadslist_sem);
	if (list_empty(&threads_list)){
		//up_read(&threadslist_sem);
		seq_printf(m, "task list is empty\n");
		return 0;
	}

	list_for_each(tsk_entry, &threads_list){
		struct task_info *tsk = container_of(tsk_entry, struct task_info, task_list);
		seq_printf(m, "pid[%d],name[%s]，tgid[%d]\n",
			tsk->pid, tsk->comm, tsk->tgid);
		list_for_each(stack_entry, &tsk->userstack_list){
			struct user_stack_detail *user_stack = (struct user_stack_detail *)stack_entry;
			loop_count++;
			syscall_name = user_stack->is_brk ? "brk" : "mmap";
			seq_printf(m, "%s,用户态堆栈%d：\n", syscall_name,loop_count);
	    	for (i = 0; i < STACK_DETAIL_DEPTH; i++) {
		    	if (user_stack->stack[i].bp == 0) {
			    	continue;
		    	}
		    	seq_printf(m,"#~   0x%lx", user_stack->stack[i].bp);
				seq_printf(m,"   %s\n",user_stack->stack[i].path);
	    	} 
		}      
	}
	//up_read(&threadslist_sem);
	return 0;
}

DEFINE_PROC_ATTRIBUTE_RO(mmaptrace_print);

static int mmaptrace_pid_show(struct seq_file *m, void *v)
{
	seq_printf(m, "pid:%d, len:%ld\n", mmap_pid, mmap_len);
	return 0;

}

static ssize_t mmaptrace_pid_store(void *priv, const char __user *buf, size_t count)
{
	struct task_struct *tsk;
	struct task_info *new_tsk;
	struct mm_struct *mm;
	struct file *vma_file;
	struct vm_area_struct *vma;
	struct vma_info *new_vma;
	struct pid *pid;
	char buffer[PROC_NUMBUF];
	char buff[PATH_LEN];
	pid_t pid_i;
	int err = -1;

	if (!enable_mmaptrace){
		pr_warn("mmaptrace disabled!");
		return count;
	}


	memset(buffer, 0, sizeof(buffer));
	if (count > sizeof(buffer) - 1)
		count = sizeof(buffer) - 1;
	if (copy_from_user(buffer, buf, count)) {
		return -EFAULT;
	}

	err = kstrtoint(strstrip(buffer), 0, &pid_i);
	if (err)
		return -EINVAL;

	if (!list_empty(&threads_list)){
		struct list_head *entry;
		list_for_each(entry, &threads_list){
			struct task_info *pos = (struct task_info *)entry;
			if (pos->pid == pid_i)
				return count;
		}
	}
	
	rcu_read_lock();
	
	pid= find_get_pid(pid_i);
	tsk = pid_task(pid, PIDTYPE_PID);
    if (!tsk || !(tsk->mm)){
       	rcu_read_unlock(); 
		return -EINVAL;
	}
	mmap_pid = pid_i;

	if (mmap_pid != 0 ){
	    new_tsk = kzalloc(sizeof(struct task_info),GFP_KERNEL);
		if (!new_tsk)
			goto failed_tsk;
	    new_tsk->pid = mmap_pid;
        new_tsk->tgid = tsk->tgid;
	    memcpy(new_tsk->comm,tsk->comm,sizeof(tsk->comm));
	    new_tsk->mmap_count++;
		//INIT_LIST_HEAD(&new_tsk->vma_list);
		INIT_LIST_HEAD(&new_tsk->userstack_list);

		mm = get_task_mm(tsk);

		if (IS_ERR_OR_NULL(mm)){
			rcu_read_unlock();
			return -EINVAL;
		}

		if (!down_read_trylock(&mm->mmap_sem)){
			rcu_read_unlock();
			return -EINTR;
		}
		for (vma = mm->mmap; vma; vma = vma->vm_next){
			//if (vma->vm_file && vma->vm_flags & VM_EXEC && !inode_open_for_write(file_inode(vma->vm_file))){
			if (vma->vm_file && vma->vm_flags & VM_EXEC){
				new_vma = kzalloc(sizeof(struct vma_info),GFP_KERNEL);
				if (!new_vma)
					goto failed_vma;
				new_vma->start = vma->vm_start;
				new_vma->pid = current->pid;
				new_vma->end = vma->vm_end;
				vma_file = vma->vm_file;

				if (vma_file){
					get_filename(buff, &vma_file->f_path, PATH_LEN);
				}
				strcpy(new_vma->path, buff);
				//(&vmalist_sem);
				list_add_tail(&new_vma->list,&threadvma_list);
				//up_write(&vmalist_sem);
			}
		}
		up_read(&mm->mmap_sem);
		//down_write(&threadslist_sem);
		list_add_tail(&new_tsk->task_list, &threads_list);
		//up_write(&threadslist_sem);
	}
	rcu_read_unlock();
	return count;
failed_vma:
	kfree(new_tsk);
failed_tsk:
	rcu_read_unlock();
	return -ENOMEM;
}

DEFINE_PROC_ATTRIBUTE_RW(mmaptrace_pid);

static ssize_t mmaptrace_len_store(void *priv, const char __user *buf, size_t count)
{
	char buffer[PROC_NUMBUF];
	unsigned long length;
	int err = -1;

	memset(buffer, 0, sizeof(buffer));
	if (count > sizeof(buffer) - 1)
		count = sizeof(buffer) - 1;
	if (copy_from_user(buffer, buf, count)) {
		return -EFAULT;
	}

	err = _kstrtoul(strstrip(buffer), 0, &length);
	if (err)
		return -EINVAL;
	mmap_len = length;
	return count;
}

static int mmaptrace_len_show(struct seq_file *m, void *v)
{
	seq_printf(m, "monitor len: %ld\n", mmap_len);
	return 0;

}

DEFINE_PROC_ATTRIBUTE_RW(mmaptrace_len);

static int before_do_brk(struct kprobe *p, struct pt_regs *regs)
{
	int ret;

	brk = 1;
	if (regs->si < mmap_len){
		return 0;
	}

	if (!current || !current->mm)
		return 0;
	ret = save_calltrace(regs);
    return 0;
}

static void after_do_brk(struct kprobe *p, struct pt_regs *regs,
                unsigned long flags)
{
	return;
}

static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	pr_info("fault_handler: p->addr = 0x%p, trap #%dn", p->addr, trapnr);
	return 0;
}

static int mmaptrace_enable(void)
{
	int ret_mmap, ret_brk;

	kp_mmap.pre_handler = before_mmap_pgoff;
	kp_mmap.post_handler = after_mmap_pgoff;
	kp_mmap.fault_handler = handler_fault;

	kp_brk.pre_handler = before_do_brk;
	kp_brk.post_handler = after_do_brk;
	kp_brk.fault_handler = handler_fault;

	ret_mmap = register_kprobe(&kp_mmap);
	if (ret_mmap < 0) {
		pr_err("register_kprobe mmap failed, returned %d\n", ret_mmap);
		return -REGISTER_FAILED;
	}

	ret_brk = register_kprobe(&kp_brk);
	if (ret_brk < 0) {
		unregister_kprobe(&kp_mmap);
		pr_err("register_kprobe  brk failed, returned %d\n", ret_brk);
		return -REGISTER_FAILED;
	}

	pr_info("Planted kprobe at %p\n", kp_mmap.addr);
	pr_info("Planted kprobe at %p\n", kp_brk.addr);
	return 0;
}

void mmaptrace_disable(void)
{
	unregister_kprobe(&kp_mmap);
	unregister_kprobe(&kp_brk);
	pr_info("kprobe at %p unregistered\n", kp_mmap.addr);
	pr_info("kprobe at %p unregistered\n", kp_brk.addr);
}

static int mmaptrace_enable_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", (int)enable_mmaptrace);
	return 0;
}

static ssize_t mmaptrace_enable_store(void *priv, const char __user *buf, size_t count)
{
	char buffer[PROC_NUMBUF];
	int val;
	int err = -1;

	memset(buffer, 0, sizeof(buffer));
	if (count > sizeof(buffer) - 1)
		count = sizeof(buffer) - 1;
	if (copy_from_user(buffer, buf, count)) {
		return -EFAULT;
	}
	err = kstrtoint(strstrip(buffer), 0, &val);

	if (val == 1){
		if (!mmaptrace_enable())
			enable_mmaptrace = true;
	}else if (val == 0){
		if (enable_mmaptrace){
			mmaptrace_disable();
			enable_mmaptrace = false;
		}
	}
	return count;
}

DEFINE_PROC_ATTRIBUTE_RW(mmaptrace_enable);

int mmaptrace_init(void)
{
	struct proc_dir_entry *parent_dir;
	struct proc_dir_entry *entry_print;
	struct proc_dir_entry *entry_pid;
	struct proc_dir_entry *entry_len;
	struct proc_dir_entry *entry_enable;

	parent_dir = sysak_proc_mkdir("mmaptrace");
	if (!parent_dir) {
		goto failed_root;
	}

	entry_print = proc_create("mmaptrace_print", 0444, parent_dir, &mmaptrace_print_fops);
    	if(!entry_print) {
    		goto failed;
	}

	entry_pid = proc_create("mmaptrace_pid", 0664, parent_dir, &mmaptrace_pid_fops);
    	if(!entry_pid) {
    		goto failed;
	}

	entry_len = proc_create("mmaptrace_len", 0444, parent_dir, &mmaptrace_len_fops);
    	if(!entry_len) {
    		goto failed;
	}

	entry_enable = proc_create("mmaptrace_enable", 0664, parent_dir, &mmaptrace_enable_fops);
    	if(!entry_enable) {
    		goto failed;
	}
	return 0;

failed:
	sysak_remove_proc_entry("mmaptrace");
failed_root:
	return -1;
}

int mmaptrace_exit(void)
{
	struct list_head *tsk_entry;
	struct list_head *vma_entry;
	struct list_head *tsk_prev;
	struct list_head *vma_prev;

	if (enable_mmaptrace){
		mmaptrace_disable();
	}

	list_for_each(tsk_entry, &threads_list){
		struct task_info *tsk = container_of(tsk_entry, struct task_info, task_list);
		tsk_prev = tsk_entry->prev;

		list_del(tsk_entry);
		kfree(tsk);
		tsk_entry = tsk_prev;
	}

	list_for_each(vma_entry, &threadvma_list){
		struct vma_info *vma = container_of(vma_entry, struct vma_info, list);
		vma_prev = vma_entry->prev;

		list_del(vma_entry);
		kfree(vma);
		vma_entry = vma_prev;
	}
	return 0;
}
#endif
