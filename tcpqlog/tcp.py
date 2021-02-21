from bcc import BPF

import signal
import sys
import os
import json
import ctypes
import time as ti

from socket import inet_ntoa, htonl, ntohs

bpf_code = """
//#define KBUILD_MODNAME "tcpcctrace"
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <bcc/proto.h>

struct data_t {
    u16 event_type;
    u16 family;
    u32 daddr;
    u32 saddr;
    u16 dport;
    u16 sport;
    u64 timestamp;
};
BPF_PERF_OUTPUT(events);
BPF_PERF_OUTPUT(rcv_events);

// syn sent
int kprobe__tcp_connect(struct pt_regs *ctx, struct sock *sk) {
    struct data_t data = {};
    data.event_type = 0;
    data.daddr = sk->sk_daddr;
    data.saddr = sk->sk_rcv_saddr;
    data.sport = sk->sk_num;
    data.dport = sk->sk_dport;
    data.family = sk->sk_family;
    data.timestamp = bpf_ktime_get_ns();
    events.perf_submit(ctx, &data, sizeof(data));
    bpf_trace_printk("syn sent %u : %u\\n", sk->sk_rcv_saddr, sk->sk_daddr);
    return 0;
}

// syn-ack sent
int kprobe__tcp_v4_send_synack(struct pt_regs *ctx, const struct sock *sk, struct dst_entry *dst, struct flowi *fl, struct request_sock *req) {
//struct sk_buff *kprobe__tcp_make_synack(struct pt_regs *ctx, const struct sock *sk, struct dst_entry *dst, struct flowi *fl, struct request_sock *req) {
    struct request_sock r;
    bpf_probe_read_kernel((void*) &r, sizeof(struct request_sock), req);
    const struct inet_request_sock *ireq = inet_rsk(&r);
    struct data_t data = {};
    data.event_type = 1;
    data.daddr = ireq->ir_rmt_addr;
    data.saddr = sk->sk_rcv_saddr;
    data.sport = sk->sk_num;
    data.dport = ireq->ir_rmt_port;
    data.family = sk->sk_family;
    data.timestamp = bpf_ktime_get_ns();
    events.perf_submit(ctx, &data, sizeof(data));
    bpf_trace_printk("synack sent %u : %u\\n", data.saddr, data.daddr);
    return 0;
}

// ack sent
//void kprobe____tcp_send_ack(struct pt_regs *ctx, struct sock *sk, u32 rcv_nxt) {
void kprobe__tcp_send_ack(struct pt_regs *ctx, struct sock *sk) {
    struct data_t data = {};
    data.event_type = 2;
    data.daddr = sk->sk_daddr;
    data.saddr = sk->sk_rcv_saddr;
    data.sport = sk->sk_num;
    data.dport = sk->sk_dport;
    data.family = sk->sk_family;
    data.timestamp = bpf_ktime_get_ns();
    events.perf_submit(ctx, &data, sizeof(data));
    bpf_trace_printk("ack sent %u : \\n", sk->sk_rcv_saddr, data.daddr);    
}

// fin sent
void kprobe__tcp_send_fin(struct pt_regs *ctx, struct sock *sk) {
    struct data_t data = {};
    data.event_type = 3;
    data.daddr = sk->sk_daddr;
    data.saddr = sk->sk_rcv_saddr;
    data.sport = sk->sk_num;
    data.dport = sk->sk_dport;
    data.family = sk->sk_family;
    data.timestamp = bpf_ktime_get_ns();
    events.perf_submit(ctx, &data, sizeof(data));
    bpf_trace_printk("fin %u\\n", sk->sk_rcv_saddr);    
}

void kprobe__tcp_v4_send_reset(struct pt_regs *ctx, const struct sock *sk, struct sk_buff *skb) {
    struct sk_buff skb_in;
    bpf_probe_read_kernel((void*) &skb_in, sizeof(struct sk_buff), skb);

    struct tcphdr *th = tcp_hdr(&skb_in);
    struct iphdr *iph = ip_hdr(&skb_in);

    struct data_t data = {};
    data.event_type = 4;
    bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr), &iph->saddr);
    bpf_probe_read_kernel(&data.saddr, sizeof(data.saddr), &iph->daddr);
    bpf_probe_read_kernel(&data.sport, sizeof(data.sport), &th->dest);
    bpf_probe_read_kernel(&data.dport, sizeof(data.dport), &th->source);
    data.sport = ntohs(data.sport);

    data.family = sk->sk_family;
    data.timestamp = bpf_ktime_get_ns();
    events.perf_submit(ctx, &data, sizeof(data));

    bpf_trace_printk("reset %u\\n", data.saddr);
}

// ack received
int kprobe__tcp_ack(struct pt_regs *ctx, struct sock *sk, const struct sk_buff *skb, int flag) {
    struct data_t data = {};
    data.event_type = 2;
    data.daddr = sk->sk_daddr;
    data.saddr = sk->sk_rcv_saddr;
    data.sport = sk->sk_num;
    data.dport = sk->sk_dport;
    data.family = sk->sk_family;

    //rcv_events.perf_submit(ctx, &data, sizeof(data));

    bpf_trace_printk("ack received %u %u\\n", sk->sk_rcv_saddr, sk->sk_daddr);
    return 0;
}

// reset received
void kprobe__tcp_reset(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    struct data_t data = {};
    data.event_type = 4;
    data.daddr = sk->sk_daddr;
    data.saddr = sk->sk_rcv_saddr;
    data.sport = sk->sk_num;
    data.dport = sk->sk_dport;
    data.family = sk->sk_family;

    rcv_events.perf_submit(ctx, &data, sizeof(data));
    bpf_trace_printk("reset received %u : %u\\n", data.saddr, data.daddr);
}

// fin received
void kprobe__tcp_fin(struct pt_regs *ctx, struct sock *sk) {
    struct data_t data = {};
    data.event_type = 3;
    data.daddr = sk->sk_daddr;
    data.saddr = sk->sk_rcv_saddr;
    data.sport = sk->sk_num;
    data.dport = sk->sk_dport;
    data.family = sk->sk_family;

    rcv_events.perf_submit(ctx, &data, sizeof(data));

    bpf_trace_printk("fin received %u : %u\\n", sk->sk_rcv_saddr, sk->sk_daddr);
}

void kprobe__tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state) {
    struct data_t data = {};
    data.event_type = state;
    data.daddr = sk->sk_daddr;
    data.saddr = sk->sk_rcv_saddr;
    data.sport = sk->sk_num;
    data.dport = sk->sk_dport;
    data.family = sk->sk_family;
    //events.perf_submit(ctx, &data, sizeof(data));
    bpf_trace_printk("state %d : %u\\n", state, sk->sk_rcv_saddr);    
}

"""

# The timestamp computation is taken 'as it is' from https://github.com/moonfalir/quicSim-docker/blob/master/tcpebpf/bccscripts/tcpprobe_congestion.py#L72
# Get timestamp of kernel boot
with open('/proc/uptime', 'r') as f:
	uptime_s = float(f.readline().split()[0])
	start_time = ti.time() - uptime_s

# Reference times for server
reference_time = -1

# Calculate time delta of event
def setTimeInfo(timestamp):
	time = 0.0
	global reference_time
	if reference_time == -1:
		reference_time = start_time + (ctypes.c_float(timestamp).value / 1000000000)
		reference_time = ti.time()
		#qlog["traces"][0]["common_fields"]["reference_time"] = reference_time
	time = reference_time - (start_time + (ctypes.c_float(timestamp).value / 1000000000))
	return reference_time - ti.time()

prev_met_upd_t = 0

events = []
trace = {'events': events}

def from_long_to_ip4(val):
    return inet_ntoa(bytes(bytearray.fromhex(hex(htonl(val))[2:])))

def sigint_handler(_sig, _frame):
    print('Kill probe')
    print(events)
    sys.exit(0)

b = BPF(text=bpf_code)

EVENT_TYPE = {
    0: 'SYN',
    1: 'SYN-ACK',
    2: 'ACK',
    3: 'FIN',
    4: 'RST',
}

def process_send_event(cpu, data, size):
    global events, prev_met_upd_t
    event = b['events'].event(data)

    header = {
            'src_ip': from_long_to_ip4(event.saddr),
            'dst_ip': from_long_to_ip4(event.daddr),
            'src_port': event.sport,
            'dst_port': ntohs(event.dport),
    }
    
    packet = {'frame_type': EVENT_TYPE[event.event_type]}

    log = ["%.6f" % (abs(prev_met_upd_t) * 1000),  'transport', 'packet_sent', {'header': header, 'frames': [packet]}]
    prev_met_upd_t = setTimeInfo(event.timestamp)

    events.append(log)
    print(log)

def process_rcv_event(cpu, data, size):
    global events, prev_met_upd_t
    event = b['events'].event(data)

    header = {
            'src_ip': from_long_to_ip4(event.saddr),
            'dst_ip': from_long_to_ip4(event.daddr),
            'src_port': event.sport,
            'dst_port': ntohs(event.dport),
    }
    
    packet = {'frame_type': EVENT_TYPE[event.event_type]}

    log = ["%.6f" % (abs(prev_met_upd_t) * 1000),  'transport', 'packet_received', {'header': header, 'frames': [packet]}]
    prev_met_upd_t = setTimeInfo(event.timestamp)

    events.append(log)
    print(log)


print("Probe added")

signal.signal(signal.SIGINT, sigint_handler)
b["events"].open_perf_buffer(process_send_event)
b["rcv_events"].open_perf_buffer(process_rcv_event)

while True:
    b.perf_buffer_poll()
