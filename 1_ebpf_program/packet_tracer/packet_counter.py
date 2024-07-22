from bcc import BPF
from time import sleep

# Load the eBPF program
bpf = BPF(src_file="count_packets.c")

# Attach the eBPF program to the ingress hook of the eth0 interface
# The "prog" section name is used to locate the eBPF function in the ELF file
bpf.attach_xdp("eth0", bpf.load_func("count_packets", BPF.XDP))

print("Tracing packets on eth0... Ctrl-C to end.")

# Read and print the packet counts from the eBPF map every second
try:
    while True:
        sleep(1)
        key = 0
        counter = bpf["pkt_counter"]
        for k, v in counter.items():
            print(f"CPU {k.value}: {v.value} packets")
except KeyboardInterrupt:
    print("Detaching...")
    bpf.remove_xdp("eth0", 0)

