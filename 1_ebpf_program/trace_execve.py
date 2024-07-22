from bcc import BPF

# Load the eBPF program
bpf = BPF(src_file="trace_execve.c")

# Attach the eBPF program to the execve system call
bpf.attach_kprobe(event="sys_execve", fn_name="trace_execve")

print("Tracing execve....")

# Print the trace output
bpf.trace_print()

