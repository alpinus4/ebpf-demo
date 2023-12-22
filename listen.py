from bcc import BPF
from bcc.utils import printb

BPF_SOURCE_CODE = r"""
TRACEPOINT_PROBE(syscalls, sys_enter_mkdir) {
   bpf_trace_printk("Hello. Creating new directory: %s\n", args->pathname);
   return 0;
}
"""

bpf = BPF(text = BPF_SOURCE_CODE)
print("Listening for directory creations...")
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = bpf.trace_fields()
        printb(b"%-6d %s" % (pid, msg))
    except ValueError:
        continue
    except KeyboardInterrupt:
        break
