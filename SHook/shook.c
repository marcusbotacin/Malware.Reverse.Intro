/*
 * Tested on kernel 4.19.0-5 (Debian 10)
 * It includes a dynamic symbol resolution for set_memory_rw/ro
 */

#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <linux/kdev_t.h>
#include <linux/kallsyms.h>
#include <linux/utsname.h>

#define CR0_WP 0x00010000   // Write-Protect Bit (CR0:16) amd64


#ifndef _LP64
#error "Only supports x86_64 kernel <=> cpu!"
#endif


MODULE_LICENSE("GPL");

void **syscall_table;

// Prototypes (strict-prototypes)

asmlinkage long (*orig_sys_uname)(struct new_utsname __user  *);
asmlinkage long hook_sys_uname(struct new_utsname __user  *);
unsigned long **find_sys_call_table(void);
static int __init syscall_init(void);
static void __exit syscall_release(void);

/*Kernel >4.1 no longer exports set_memory_r*, here it's a fix :)*/
static int (*do_set_memory_rw)(unsigned long addr, int numpages) = NULL;
static int (*do_set_memory_ro)(unsigned long addr, int numpages) = NULL;


unsigned long **find_sys_call_table()
{

    unsigned long ptr;
    unsigned long *p;
    static long (*sys_close) (unsigned int fd)=NULL;

    sys_close=(void *)kallsyms_lookup_name("sys_close");
    if (!sys_close)
    {
        printk(KERN_DEBUG "[HOOK] Symbol sys_close not found\n");
        return NULL;
    }

    /* the sys_call_table can be found between the addresses of sys_close
     * and loops_pre_jiffy. Look at /boot/System.map or /proc/kallsyms to
     * see if it is the case for your kernel */

    for (ptr = (unsigned long)sys_close;
            ptr < (unsigned long)&loops_per_jiffy;
            ptr += sizeof(void *))
    {

        p = (unsigned long *)ptr;

        /* Indexes such as __NR_close can be found in
         * /usr/include/x86_64-linux-gnu/asm/unistd{,_64}.h
         * syscalls function can be found in
         * /usr/src/`uname -r`/include/linux/syscalls.h */
        if (p[__NR_close] == (unsigned long)sys_close)
        {
            /* the address of the ksys_close function is equal to the one found
             * in the sys_call_table */
            printk(KERN_DEBUG "[HOOK] Found the sys_call_table!!!\n");
            return (unsigned long **)p;
        }
    }

    return NULL;
}

/* This is an example of a syscall interposition function,
 *  it was write to exemplify user <I/O> kernel buffers as well.
 */
asmlinkage long hook_sys_uname(struct new_utsname __user *name)
{
    char msg[5]="Hook\0";
    struct new_utsname tmp;

    printk(KERN_DEBUG "[HOOK] Inside hook_sys_uname\n");

    // Call the kernel syscall implementation before change buffer content
    orig_sys_uname(name);

    /* Check if the buffer is valid in userland and as well tries to copy
     * its content to a local buffer before change it.
     * It is not safe to directly R/W userland's data in kerneland
     */
    if(!copy_from_user(&tmp,name,sizeof(tmp)))
    {

        printk(KERN_DEBUG "[HOOK] uname->sysname: %s\n",tmp.sysname);
        memcpy(tmp.sysname,msg,5);
        if(copy_to_user(name,&tmp,sizeof(tmp)))
            printk(KERN_DEBUG "[HOOK] Can't write to user-buffer!\n");
    }
    else
        printk(KERN_DEBUG "[HOOK] Can't copy user-buffer :(\n");
    return 0;
}


static int __init syscall_init(void)
{
    int ret;
    unsigned long cr0;

    /* get the sys_call_table address */
    syscall_table = (void **)find_sys_call_table();

    /* Starting on version 4.17, the kernel no long exports any syscall
     * symbol. The following solution only works if debug information is present in the
     * running kernel.*/

    if (!syscall_table)
    {
        printk(KERN_DEBUG "[HOOK] Trying sys_call_table symbol\n");
        syscall_table=(void **)kallsyms_lookup_name("sys_call_table");
        if (!syscall_table)
        {
            printk(KERN_DEBUG "[HOOK] Cannot find the sys_call_table address\n");
            return -EINVAL;
        }
    }

    printk(KERN_DEBUG "[HOOK] System call table at 0x%16lx\n",(unsigned long)syscall_table);
    /* get the value of the CR0 register */
    cr0 = read_cr0();
    /* disable the Write-Protect bit */
    write_cr0(cr0 & (~CR0_WP));
    /*set the memory covered by the sys_call_table writable */

    do_set_memory_rw = (void *)kallsyms_lookup_name("set_memory_rw");
    do_set_memory_ro = (void *)kallsyms_lookup_name("set_memory_ro");
    if (do_set_memory_rw == NULL)
    {
        printk(KERN_DEBUG "[HOOK] Symbol not found: 'set_memory_rw'\n");
        return -EINVAL;
    }

    ret = do_set_memory_rw(PAGE_ALIGN((unsigned long)syscall_table),1);

    if(ret)
    {
        printk(KERN_DEBUG
               "[HOOK] Cannot set the memory to rw (%d) at addr 0x%16lx\n",
               ret, PAGE_ALIGN((unsigned long)syscall_table));
        return -EINVAL;
    }
    else
    {
        printk(KERN_DEBUG "[HOOK] Syscall Table page set to rw\n");
    }


    /* Hooking*/
    orig_sys_uname = syscall_table[__NR_uname];
    syscall_table[__NR_uname] = hook_sys_uname;
    printk(KERN_DEBUG "[HOOK] sys_uname: 0x%16lx - hook_sys_uname: 0x%16lx\n",(unsigned long)orig_sys_uname,(unsigned long)hook_sys_uname);

    /* restore the Write-Protect bit */
    write_cr0(cr0);
    return 0;
}


static void __exit syscall_release(void)
{
    unsigned long cr0;
    /* get the value of the CR0 register */
    cr0 = read_cr0();
    /* disable the Write-Protect bit */
    write_cr0(cr0 & ~CR0_WP);
    syscall_table[__NR_uname] = orig_sys_uname;
    /* restore syscall table page RO mask */
    do_set_memory_ro(PAGE_ALIGN((unsigned long) syscall_table),1);
    /* restore the Write-Protect bit */
    write_cr0(cr0);
    printk(KERN_DEBUG "[HOOK] released module\n");
}

module_init(syscall_init);
module_exit(syscall_release);
