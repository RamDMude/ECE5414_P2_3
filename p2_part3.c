/* vim: set ts=8 sw=8 noexpandtab: */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/hashtable.h>
#include <linux/types.h>
#include <linux/kprobes.h>
#include <linux/stacktrace.h>
#include <linux/rbtree.h>
#include <linux/jhash.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ram Mude");
MODULE_DESCRIPTION("LKP25 P2");

extern unsigned int stack_trace_save_user(unsigned long *store, unsigned int size);


#define MAX_STACK_TRACE 16
#define MAX_DEPTH 16
#define MAX_TOP_TASKS 20

static struct rb_root sched_rbtree = RB_ROOT;


struct sched_rbentry {
    struct rb_node node;
    u64 exec_time;
    u32 stack_hash;
    unsigned long stack_entries[MAX_STACK_TRACE];
    unsigned int nr_entries;
};


static char symbol2[KSYM_NAME_LEN] = "pick_next_task_fair";
module_param_string(symbol2, symbol2, KSYM_NAME_LEN, 0644);

static struct kprobe kp2 = {
	.symbol_name	= symbol2,
};

static struct task_struct *prev_task = NULL;
static u64 prev_timestamp = 0;

static struct sched_rbentry *rbtree_lookup(unsigned int nr_entries, unsigned long *entries) {
    struct rb_node *node = sched_rbtree.rb_node;

    // while (node) {
    //     struct sched_rbentry *entry = container_of(node, struct sched_rbentry, node);
    //     int cmp = memcmp(entry->stack_entries, entries, nr_entries * sizeof(unsigned long));

    //     if (entry->nr_entries == nr_entries && cmp == 0) {
    //         return entry;
    //     }

    //     if (cmp < 0)
    //         node = node->rb_right;entries
    //     else
    //         node = node->rb_left;
    // }



    for (node = rb_first(&sched_rbtree); node; node= rb_next(node)){
        struct sched_rbentry *entry = container_of(node, struct sched_rbentry, node);
        if (entry->nr_entries == nr_entries && !memcmp(entry->stack_entries, entries, nr_entries * sizeof(unsigned long))){
            return entry;
        }
    }
    
    return NULL;
}

static void rbtree_insert(unsigned int nr_entries, unsigned long *entries, u64 exec_time, u32 stack_hash) {
    struct rb_node **link = &sched_rbtree.rb_node, *parent = NULL;
    struct sched_rbentry *new_node = kmalloc(sizeof(struct sched_rbentry ), GFP_KERNEL);

    if (!new_node){
        return;
    }
    new_node -> nr_entries = nr_entries;
    memcpy(new_node->stack_entries, entries, nr_entries * sizeof(unsigned long));
    new_node -> exec_time = exec_time;
    new_node -> stack_hash = stack_hash;


    while (*link) {
        struct sched_rbentry *entry = container_of(*link, struct sched_rbentry, node);
        parent = *link;

        if (exec_time < entry->exec_time)
            link = &((*link)->rb_left);
        else if (exec_time > entry->exec_time)
            link = &((*link)->rb_right);
        else {
            return; // Duplicate entry, do not insert
        }
    }

    rb_link_node(&new_node->node, parent, link);
    rb_insert_color(&new_node->node, &sched_rbtree);
    
    return;
}

static void rbtree_remove(struct sched_rbentry *entry) {

    rb_erase(&entry->node, &sched_rbtree);
    
    kfree(entry);
    return;
}

static void __kprobes handler_post2(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    struct task_struct *curr = (struct task_struct *)regs->si;
    if (!curr){ 
        return;
    }

    unsigned long entries[MAX_STACK_TRACE];
	unsigned int nr_entries;

    u64 now = ktime_get_ns();
    if (prev_task && prev_timestamp){
        u64 elapsed = now - prev_timestamp;
    
        if (user_mode(regs)){
            nr_entries = stack_trace_save_user(entries, MAX_STACK_TRACE);
        }
        else{
            nr_entries = stack_trace_save(entries, MAX_STACK_TRACE, 0 );
        }
        
        u32 stack_hash = jhash(entries, nr_entries * sizeof(unsigned long), 0);

        
        struct sched_rbentry *old_entry = rbtree_lookup(nr_entries, entries);
        u64 execution_time = 0;
        if (old_entry){
            execution_time = old_entry->exec_time + elapsed;    
            rbtree_remove(old_entry);
        }
        execution_time = elapsed;
        
        rbtree_insert(nr_entries, entries, execution_time, stack_hash);
    }
    prev_task = curr;
    prev_timestamp = now;
	return;
}

static int lkp25_p2_proc_show(struct seq_file *m, void *v)
{
	struct rb_node *node;
    int count = 0;
    
    seq_puts(m, "Rank\tJenkins Hash\tTotal CPU Time (ns)\tStack Trace\n");

    for (node = rb_last(&sched_rbtree); node && (count < MAX_TOP_TASKS); node = rb_prev(node), count++) {
        struct sched_rbentry *entry = container_of(node, struct sched_rbentry, node);
        seq_printf(m, "Rank :%d\n%u\n%llu\n", count + 1, entry->stack_hash, entry->exec_time);
        for (int i = 0; i < min(entry->nr_entries, MAX_DEPTH); i++)
            seq_printf(m, "%pB \n", (void *)entry->stack_entries[i]);
        seq_puts(m, "\n");
    }
    return 0;
}

static void cleanup_rbtree(void) {
    struct rb_node *node, *next;
    for (node = rb_first(&sched_rbtree); node; node = next) {
        struct sched_rbentry *entry = container_of(node, struct sched_rbentry, node);
        next = rb_next(node);
        rb_erase(node, &sched_rbtree);
        kfree(entry);
    }

}

static int lkp25_p2_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, lkp25_p2_proc_show, NULL);
}

static const struct proc_ops lkp25_p2_proc_fops = {
	.proc_open = lkp25_p2_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int __init lkp25_p2_init(void)
{
	int ret;

	printk(KERN_INFO "lkp_p2 Module Loaded");
	/* Create our /proc/perftop file */
	proc_create("perftop", 0, NULL, &lkp25_p2_proc_fops); 


	kp2.post_handler = handler_post2;

	ret = register_kprobe(&kp2);
	if (ret < 0) {
		pr_err("register_kprobe failed, returned %d\n", ret);
		return ret;
	}
	printk(KERN_INFO "Planted scheduler kprobe at %p\n", kp2.addr);

	return 0;
}

static void __exit lkp25_p2_exit(void)
{
	/* Remove the /proc/perftop entry */
	unregister_kprobe(&kp2);
	printk(KERN_INFO "Scheduler kprobe at %p unregistered\n", kp2.addr);
	
    cleanup_rbtree();
	remove_proc_entry("perftop", NULL);
	printk(KERN_INFO "lkp_p2 Module Unloaded");
}

module_init(lkp25_p2_init);
module_exit(lkp25_p2_exit);
