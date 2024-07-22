#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

int trace_execve(struct pt_regs *ctx, const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp) {
    bpf_trace_printk("execve called: %s\n", filename);
    return 0;
}