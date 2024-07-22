from bcc import BPF
from time import sleep

# Load the eBPF program
bpf = BPF(src_file="count_openat.c")

# Attach the eBPF program to the openat syscall tracepoint
bpf.attach_tracepoint(tp="syscalls:sys_enter_openat", fn_name="count_openat")

print("Tracing openat syscalls... Ctrl-C to end.")

# Read and print the counter value every second
try:
    while True:
        sleep(1)
        key = 0
        counter = bpf["openat_counter"]
        for k, v in counter.items():
            print(f"Openat syscall count: {v.value}")
except KeyboardInterrupt:
    print("Detaching...")

