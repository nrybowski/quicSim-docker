from bcc import BPF, tcp

import signal
import sys
import os
import json
import ctypes
import time as ti
import hashlib
import time

from socket import inet_ntoa, htonl, ntohs

bpf_code = """

#define VIRTME_DEBUG

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <bcc/proto.h>
#include <net/mptcp.h>

#define MPTCPOPT_HMAC_LEN	20

struct data_t {
    u16 family;

    u32 daddr;
    u32 saddr;
    u16 dport;
    u16 sport;

    u32 parent_daddr;
    u32 parent_saddr;
    u16 parent_dport;
    u16 parent_sport;

    u64 timestamp;

    u32 seq, ack_seq, end_seq;
    
    u8 flags;
    u16 win;

    u64 sk;

    u8 proto : 1;
};

// https://elixir.bootlin.com/linux/v5.12/source/net/mptcp/protocol.h#L388
enum mptcp_data_avail {
	MPTCP_SUBFLOW_NODATA,
	MPTCP_SUBFLOW_DATA_AVAIL,
	MPTCP_SUBFLOW_OOO_DATA
};

struct mptcp_subflow_context {
	struct	list_head node;/* conn_list of subflows */
	u64	local_key;
	u64	remote_key;
	u64	idsn;
	u64	map_seq;
	u32	snd_isn;
	u32	token;
	u32	rel_write_seq;
	u32	map_subflow_seq;
	u32	ssn_offset;
	u32	map_data_len;
	u32	request_mptcp : 1,  /* send MP_CAPABLE */
		request_join : 1,   /* send MP_JOIN */
		request_bkup : 1,
		mp_capable : 1,	    /* remote is MPTCP capable */
		mp_join : 1,	    /* remote is JOINing */
		fully_established : 1,	    /* path validated */
		pm_notified : 1,    /* PM hook called for established status */
		conn_finished : 1,
		map_valid : 1,
		mpc_map : 1,
		backup : 1,
		send_mp_prio : 1,
		rx_eof : 1,
		can_ack : 1,        /* only after processing the remote a key */
		disposable : 1;	    /* ctx can be free at ulp release time */
	enum mptcp_data_avail data_avail;
	u32	remote_nonce;
	u64	thmac;
	u32	local_nonce;
	u32	remote_token;
	u8	hmac[MPTCPOPT_HMAC_LEN];
	u8	local_id;
	u8	remote_id;

	long	delegated_status;
	struct	list_head delegated_node;   /* link into delegated_action, protected by local BH */

	struct	sock *tcp_sock;	    /* tcp sk backpointer */
	struct	sock *conn;	    /* parent mptcp_sock */
	const	struct inet_connection_sock_af_ops *icsk_af_ops;
	void	(*tcp_data_ready)(struct sock *sk);
	void	(*tcp_state_change)(struct sock *sk);
	void	(*tcp_write_space)(struct sock *sk);
	void	(*tcp_error_report)(struct sock *sk);

	struct	rcu_head rcu;
};

BPF_PERF_OUTPUT(events);
BPF_PERF_OUTPUT(rcv_events);

/*  tcp_transmit_skb is the common function used to send skbs in 
    tcp_connect aka 'SYN sent' (https://elixir.bootlin.com/linux/v5.11/source/net/ipv4/tcp_output.c#L3856)
    tcp_send_ack aka 'ACK sent' (https://elixir.bootlin.com/linux/v5.11/source/net/ipv4/tcp_output.c#L3974) 
*/
int kprobe____tcp_transmit_skb(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb, int clone_it, gfp_t gfp_mask, u32 rcv_nxt) {
    u64 timestamp = bpf_ktime_get_ns();

    struct data_t data = {};
    struct sk_buff skb_in;
    struct tcphdr* th; 

    struct tcp_skb_cb* cb = TCP_SKB_CB(&skb_in);

    data.timestamp = timestamp;
    data.daddr = sk->sk_daddr;
    data.saddr = sk->sk_rcv_saddr;
    data.sport = sk->sk_num;
    data.dport = sk->sk_dport;
    
    data.family = sk->sk_family;

    bpf_probe_read_kernel((void*) &skb_in, sizeof(struct sk_buff), skb);
    th = tcp_hdr(&skb_in);
    data.flags = cb->tcp_flags;

    data.seq = cb->seq;
    data.end_seq = cb->end_seq;
    data.ack_seq = rcv_nxt;
    data.sk = (u64) sk;
    bpf_probe_read_kernel(&data.win, sizeof(u16), &th->window);
    data.win = ntohs(data.win);

    struct tcp_sock *tsk = (struct tcp_sock*) sk;
    data.proto = tsk->is_mptcp;
    if (tsk->is_mptcp) {
        struct inet_connection_sock *icsk = inet_csk(sk);
        struct mptcp_subflow_context *subflow = (__force struct mptcp_subflow_context *)icsk->icsk_ulp_data;
        struct sock *psk = subflow->conn; // parent sk
        //bpf_trace_printk("parent %u, %u, %u", data.flags, psk->sk_daddr, psk->sk_rcv_saddr);
        //bpf_trace_printk("child %u, %u\\n", sk->sk_daddr, sk->sk_rcv_saddr);
        data.parent_daddr = psk->sk_daddr;
        data.parent_saddr = psk->sk_rcv_saddr;
        data.parent_sport = psk->sk_num;
        data.parent_dport = psk->sk_dport;
    }

    events.perf_submit(ctx, &data, sizeof(struct data_t));
 
#ifdef DEBUG
    bpf_trace_printk("TRANSMIT %u %u %u", data.saddr, data.daddr, data.flags);
    bpf_trace_printk("win %u", data.win);
    bpf_trace_printk("sk %p", sk);
    bpf_trace_printk("sport %u, dport %u", data.sport, ntohs(data.dport));
    bpf_trace_printk("seq %u, end_seq %u, ack_seq %u\\n", data.seq, data.end_seq, data.ack_seq);
#endif 

    return 0;
}

/*  syn-ack sent
    tcp_send_ack is used for the majority of outgoing packets (FIN, PSH) but except for SYN-ACK sending so we have to track this function
*/
struct sk_buff *kretprobe__tcp_make_synack(struct pt_regs *ctx) {
    u64 timestamp = bpf_ktime_get_ns();

    struct sk_buff *skb = (struct sk_buff*) PT_REGS_RC(ctx);

    // If skb for synack successfully created
    if (skb != NULL) {
        struct data_t data = {};
        struct sk_buff skb_in;
        struct tcp_skb_cb *cb;
        struct tcphdr *th;

        // Copy skb on BPF stack
        bpf_probe_read_kernel((void*) &skb_in, sizeof(struct sk_buff), skb);
        cb = TCP_SKB_CB(&skb_in);
        th = tcp_hdr(&skb_in);
        struct sock *sk = skb->sk;

        data.timestamp = timestamp;
        // addresses are inverted to for the connection key in userspace
        //data.saddr = sk->sk_daddr;
        //data.daddr = sk->sk_rcv_saddr;
        data.daddr = sk->sk_daddr;
        data.saddr = sk->sk_rcv_saddr;
        data.family = sk->sk_family;
        data.sport = sk->sk_num;
        data.dport = sk->sk_dport;
        bpf_probe_read_kernel(&data.win, sizeof(u16), &th->window);
        data.win = ntohs(data.win);
        //bpf_probe_read_kernel(&data.dport, sizeof(data.dport), &sk->sk_num);
        //bpf_probe_read_kernel(&data.sport, sizeof(data.sport), &sk->sk_dport);
        //data.sport = ntohs(data.sport);
        //data.dport = htons(data.dport);

        // Get TCP header flags
        bpf_probe_read((void*) &data.flags, sizeof(u8), &((u_int8_t *)th)[13]);

        // Get TCP header seqno and ack_seqno
        bpf_probe_read_kernel(&data.seq, sizeof(th->seq),&th->seq);
        bpf_probe_read_kernel(&data.ack_seq, sizeof(th->ack_seq), &th->ack_seq);
        data.ack_seq = ntohl(data.ack_seq);
        data.seq = ntohl(data.seq);

        // Send data to userspace
        events.perf_submit(ctx, &data, sizeof(struct data_t));

        // Debug
#ifdef DEBUG
        bpf_trace_printk("SYN-ACK sent %u %u %u", data.saddr, data.daddr, data.flags);
        bpf_trace_printk("win %u", data.win);
        bpf_trace_printk("sport %u, dport %u", data.sport, ntohs(data.dport));
        bpf_trace_printk("seq %u, end_seq %u, ack_seq %u\\n", data.seq, data.end_seq, data.ack_seq);
#endif
    }

    return skb;
}

void kprobe__tcp_v4_send_reset(struct pt_regs *ctx, const struct sock *sk, struct sk_buff *skb) {
    struct sk_buff skb_in;
    bpf_probe_read_kernel((void*) &skb_in, sizeof(struct sk_buff), skb);

    struct tcphdr *th = tcp_hdr(&skb_in);
    struct iphdr *iph = ip_hdr(&skb_in);

    struct data_t data = {};
    bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr), &iph->saddr);
    bpf_probe_read_kernel(&data.saddr, sizeof(data.saddr), &iph->daddr);
    bpf_probe_read_kernel(&data.sport, sizeof(data.sport), &th->dest);
    bpf_probe_read_kernel(&data.dport, sizeof(data.dport), &th->source);
    data.sport = ntohs(data.sport);

    data.family = sk->sk_family;
    data.timestamp = bpf_ktime_get_ns();
    //events.perf_submit(ctx, &data, sizeof(data));

#ifdef DEBUG
    bpf_trace_printk("RST sent %u %u %u", data.saddr, data.daddr, data.flags);
    bpf_trace_printk("sport %u, dport %u", data.sport, ntohs(data.dport));
    bpf_trace_printk("seq %u, end_seq %u, ack_seq %u\\n", data.seq, data.end_seq, data.ack_seq);
#endif
}

// syn received
int kprobe__tcp_conn_request(struct pt_regs *ctx, struct request_sock_ops *rsk_ops, const struct tcp_request_sock_ops *af_ops, struct sock *sk, struct sk_buff *skb)
{
    u64 timestamp = bpf_ktime_get_ns();

    struct data_t data = {};
    struct sk_buff skb_in;
    bpf_probe_read((void*) &skb_in, sizeof(struct sk_buff), skb);
    struct iphdr* iph = ip_hdr(&skb_in);
    struct tcphdr* th = tcp_hdr(&skb_in);

    // Read incoming TCP header data
    bpf_probe_read(&data.saddr, sizeof(__be32), &iph->saddr);               // get saddr
    bpf_probe_read(&data.daddr, sizeof(__be32), &iph->daddr);               // get daddr
    bpf_probe_read((void*) &data.flags, sizeof(u8), &((u_int8_t *)th)[13]); // get flags
    bpf_probe_read_kernel(&data.sport, sizeof(data.sport), &th->source);    // get sport
    bpf_probe_read_kernel(&data.dport, sizeof(data.dport), &th->dest);      // get dport
    bpf_probe_read(&data.ack_seq, sizeof(u32), &th->ack_seq);               // get ack_seqno
    bpf_probe_read(&data.seq, sizeof(u32), &th->seq);                       // get seqno

    // Conversion
    //data.dport = ntohs(data.dport);
    data.sport = ntohs(data.sport);
    data.ack_seq = ntohl(data.ack_seq);
    data.seq = ntohl(data.seq);

    bpf_probe_read_kernel(&data.win, sizeof(u16), &th->window);
    data.win = ntohs(data.win);

    data.family = sk->sk_family;
    data.timestamp = timestamp;

    struct tcp_sock *tsk = (struct tcp_sock*) sk;
    data.proto = tsk->is_mptcp;
    if (tsk->is_mptcp) {
        struct inet_connection_sock *icsk = inet_csk(sk);
        struct mptcp_subflow_context *subflow = (__force struct mptcp_subflow_context *)icsk->icsk_ulp_data;
        struct sock *psk = subflow->conn; // parent sk
        //bpf_trace_printk("parent %u, %u, %u", data.flags, psk->sk_daddr, psk->sk_rcv_saddr);
        //bpf_trace_printk("child %u, %u\\n", sk->sk_daddr, sk->sk_rcv_saddr);
        data.parent_daddr = psk->sk_daddr;
        data.parent_saddr = psk->sk_rcv_saddr;
        data.parent_sport = psk->sk_num;
        data.parent_dport = psk->sk_dport;
    }

    rcv_events.perf_submit(ctx, &data, sizeof(data));

#ifdef DEBUG
    bpf_trace_printk("SYN received, %u %u %u", data.saddr, data.daddr, data.flags);
    bpf_trace_printk("win %u", data.win);
    bpf_trace_printk("sport %u, dport %u", data.sport, ntohs(data.dport));
    bpf_trace_printk("seq %u, end_seq %u, ack_seq %u\\n", data.seq, data.end_seq, data.ack_seq);
#endif

    return 0;
}

// ack received
int kprobe__tcp_ack(struct pt_regs *ctx, struct sock *sk, const struct sk_buff *skb, int flag) {
    u64 timestamp = bpf_ktime_get_ns();

    struct data_t data = {};
    struct sk_buff skb_in;
    bpf_probe_read_kernel((void*) &skb_in, sizeof(struct sk_buff), skb);

    struct tcphdr* th = tcp_hdr(&skb_in);
    struct tcp_skb_cb* cb = TCP_SKB_CB(&skb_in);
    struct tcp_sock* tsk = tcp_sk(sk);

    data.timestamp = timestamp;

    bpf_probe_read((void*) &data.flags, sizeof(u8), &((u_int8_t *)th)[13]);

    bpf_probe_read_kernel(&data.ack_seq, sizeof(u32), &th->ack_seq);
    bpf_probe_read_kernel(&data.seq, sizeof(u32), &th->seq);
    data.ack_seq = ntohl(data.ack_seq);
    data.seq = ntohl(data.seq);

    data.saddr = sk->sk_rcv_saddr;
    data.daddr = sk->sk_daddr;
    data.sport = sk->sk_num;
    data.dport = sk->sk_dport;
    data.family = sk->sk_family;

    bpf_probe_read_kernel(&data.win, sizeof(u16), &th->window);
    data.win = ntohs(data.win);

    u32 cb_seq, cb_end_seq;
    bpf_probe_read((void*) &cb_seq, sizeof(u32), &cb->seq);
    bpf_probe_read((void*) &cb_end_seq, sizeof(u32), &cb->end_seq);
    data.end_seq = cb_end_seq;

    // If received FIN-ACK, ignore it, it will be treated later via another kfunction call
    //if (!(data.flags & 0x1))
    data.proto = tsk->is_mptcp;
    if (tsk->is_mptcp) {
        struct inet_connection_sock *icsk = inet_csk(sk);
        struct mptcp_subflow_context *subflow = (__force struct mptcp_subflow_context *)icsk->icsk_ulp_data;
        struct sock *psk = subflow->conn; // parent sk
        //bpf_trace_printk("parent %u, %u, %u", data.flags, psk->sk_daddr, psk->sk_rcv_saddr);
        //bpf_trace_printk("child %u, %u\\n", sk->sk_daddr, sk->sk_rcv_saddr);
        data.parent_daddr = psk->sk_daddr;
        data.parent_saddr = psk->sk_rcv_saddr;
        data.parent_sport = psk->sk_num;
        data.parent_dport = psk->sk_dport;
    }
        rcv_events.perf_submit(ctx, &data, sizeof(struct data_t));

#ifdef DEBUG
    bpf_trace_printk("ACK received %u %u %u", data.saddr, data.daddr, data.flags);
    bpf_trace_printk("win %u", data.win);
    bpf_trace_printk("sport %u, dport %u", data.sport, ntohs(data.dport));
    bpf_trace_printk("cb_seq %u, cb_end_seq %u", cb_seq, cb_end_seq);
    bpf_trace_printk("seq %u, end_seq %u, ack_seq %u", data.seq, data.end_seq, data.ack_seq);
    bpf_trace_printk("bytes received %u, rcv_next %u, bytes acked %u",
        tsk->bytes_received, tsk->rcv_nxt, tsk->bytes_acked
    );
    bpf_trace_printk("rcv_wup %u, snd_una %u, snd_next %u\\n", tsk->rcv_wup, tsk->snd_una, tsk->snd_nxt);
#endif

    return 0;
}

// reset received
void kprobe__tcp_reset(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    u64 timestamp = bpf_ktime_get_ns();

    struct data_t data = {};
    struct sk_buff skb_in;
    bpf_probe_read((void*) &skb_in, sizeof(struct sk_buff), skb);
    struct tcphdr* th = tcp_hdr(&skb_in);
    struct tcp_skb_cb* cb = TCP_SKB_CB(&skb_in);

    data.timestamp = timestamp;
    data.daddr = sk->sk_daddr;
    data.saddr = sk->sk_rcv_saddr;
    data.sport = sk->sk_num;
    data.dport = sk->sk_dport;
    data.family = sk->sk_family;
    bpf_probe_read((void*) &data.flags, sizeof(u8), &((u_int8_t *)th)[13]);

    bpf_probe_read_kernel(&data.win, sizeof(u16), &th->window);
    data.win = ntohs(data.win);

    bpf_probe_read((void*) &data.end_seq, sizeof(u32), &cb->end_seq);

    bpf_probe_read_kernel(&data.ack_seq, sizeof(u32), &th->ack_seq);
    bpf_probe_read_kernel(&data.seq, sizeof(u32), &th->seq);
    data.ack_seq = ntohl(data.ack_seq);
    data.seq = ntohl(data.seq);

    struct tcp_sock *tsk = (struct tcp_sock*) sk;
    data.proto = tsk->is_mptcp;
    if (tsk->is_mptcp) {
        struct inet_connection_sock *icsk = inet_csk(sk);
        struct mptcp_subflow_context *subflow = (__force struct mptcp_subflow_context *)icsk->icsk_ulp_data;
        struct sock *psk = subflow->conn; // parent sk
        //bpf_trace_printk("parent %u, %u, %u", data.flags, psk->sk_daddr, psk->sk_rcv_saddr);
        //bpf_trace_printk("child %u, %u\\n", sk->sk_daddr, sk->sk_rcv_saddr);
        data.parent_daddr = psk->sk_daddr;
        data.parent_saddr = psk->sk_rcv_saddr;
        data.parent_sport = psk->sk_num;
        data.parent_dport = psk->sk_dport;
    }

    rcv_events.perf_submit(ctx, &data, sizeof(data));

#ifdef DEBUG
    bpf_trace_printk("RST received %u : %u\\n", data.saddr, data.daddr);
    bpf_trace_printk("win %u", data.win);
    bpf_trace_printk("sport %u, dport %u", data.sport, ntohs(data.dport));
    bpf_trace_printk("seq %u, end_seq %u, ack_seq %u\\n", data.seq, data.end_seq, data.ack_seq);
#endif
}

//void kretprobe__tcp_close(struct pt_regs* ctx) {
    
//}

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

traces = {}
events = []
trace = {'events': events}

output_file = open('/mnt/test.qlog', 'w')

def from_long_to_ip4(val):
    return inet_ntoa(bytes(bytearray.fromhex(hex(htonl(val))[2:])))

b = BPF(text=bpf_code)
c = {}

def format_seq_no(events):
    # sort events by timestamp
    events.sort()
    #initial_timestamp = events[0][0]
    
    # normal connection, events[1] should be SYN and events[2] should be SYN-ACK

    if events[1][2] == 'packet_sent':
        local = events[1][3]['header']['seq']
        remote = events[2][3]['header']['seq']
    else:
        local = events[2][3]['header']['seq']
        remote = events[1][3]['header']['seq']

    h = ''
    for event in events:
        event.append(h)
        print(event)
        if event[1] == 'connectivity' and 'connection_started' in event[2]:
            #conn_data_raw = event[3]
            #conn_data = [conn_data_raw['src_ip'], conn_data_raw['src_port'], conn_data_raw['dst_ip'], conn_data_raw['dst_port']]
            #h = hashlib.md5(json.dumps(conn_data).encode('utf8')).hexdigest()
            h = event[4]
            event.pop()
        elif event[1] == 'transport':
            header = event[3]['header']
            if 'ACK' in header['flags']:
                if 'SYN' in header['flags']:
                    del header['end_seq']
                else:
                    header['ack'] -= (remote if event[2] == 'packet_sent' else local)
                    try:
                        seq = header['seq'] - (local if event[2] == 'packet_sent' else remote)
                        header['seq'] = [seq]
                        try:
                            if 'FIN' not in header['flags']:
                                end_seq = header['end_seq'] - (local if event[2] == 'packet_sent' else remote)
                                header['seq'].append(end_seq)
                            del header['end_seq']
                            if len(header['seq']) == 1 or header['seq'][0] == header['seq'][1]:
                                header['seq'] = header['seq'][0]
                        except KeyError:
                            pass
                    except KeyError:
                        pass
        
        #event[0] -= initial_timestamp
        #event[0] /= pow(10, 6)
        print('%s\n\n' % event)
    print(events)
    #json.dump(events, output_file)
    return events

meta = {}

def sigint_handler(_sig, _frame):
    print('Kill probe')
    #print(traces)
    #print('\nmeta : %s\n' % meta)
    qlog_data = {'events': []}
    for conn in traces.values():
        qlog_data['events'].append(format_seq_no(conn))
    #print(qlog_data)
    json.dump(qlog_data, output_file)
    output_file.close()
    print('Dump end')
    sys.exit(0)

def process_event(cpu, data, size, event_type):
    if event_type not in ['snt', 'rcv']:
        return
    
    global events, prev_met_upd_t
    if event_type == 'snt':
        event = b['events'].event(data)
    elif event_type == 'rcv':
        event = b['rcv_events'].event(data)

    #timestamp = "%.6f" % (abs(prev_met_upd_t) * 1000)
    #prev_met_upd_t = setTimeInfo(event.timestamp)
    timestamp = event.timestamp

    connection = {
            'src_ip': from_long_to_ip4(event.saddr),
            'dst_ip': from_long_to_ip4(event.daddr),
            'src_port': event.sport,
            'dst_port': ntohs(event.dport),
            'transport_protocol': 'TCP',
            #'transport_protocol': '%sTCP' % ('MP' if event.proto == 1 else ''),
            'ip_version': '4' if event.family == 2 else '6'
    }

    if event.sk != 0:
        try:
            if connection not in meta[event.sk]:
                meta[event.sk].append(connection)
        except KeyError:
            meta[event.sk] = [connection]

    header = {'flags': tcp.flags2str(event.flags).split('|')}

    # special case on send RST-ACK, the src port is not defined but is retrieved 
    # through the socket which is used for the connection
    if connection['src_port'] == 0 and event.sk in meta:
        # TODO : check if multiple co collected on the sk
        connection['src_port'] = meta[event.sk][0]['src_port']
        print(header['flags'])
        print(connection)

    connection = dict(sorted(connection.items()))
    fco = frozenset(connection.items())

    if 'SYN' in header['flags']:
        header['seq'] = event.seq
        if len(header['flags']) == 1:
            connectivity_type = '%sconnection_started' % ('subflow_' if event.proto and (event.parent_saddr != event.saddr or event.parent_daddr != event.daddr) and event.parent_saddr != 0 and event.parent_daddr != 0 else '')

            conn_data = [connection['src_ip'], connection['src_port'], connection['dst_ip'], connection['dst_port']]
            group_id = hashlib.md5(json.dumps(conn_data).encode('utf8')).hexdigest()
            log = [timestamp, 'connectivity', connectivity_type, connection, group_id]
            if event.proto == 1 and 'subflow' in connectivity_type:
                # add parent hash if subflow creation
                parent_id = [from_long_to_ip4(event.parent_saddr), event.parent_sport, from_long_to_ip4(event.parent_daddr), ntohs(event.parent_dport)]
                print(parent_id)
                log.append(hashlib.md5(json.dumps(parent_id).encode('utf8')).hexdigest())

            events.append(log)
            if event_type == 'rcv':
                new_co = {
                    'src_ip': connection['dst_ip'],
                    'dst_ip': connection['src_ip'],
                    'src_port': connection['dst_port'],
                    'dst_port': connection['src_port'],
                    'transport_protocol': connection['transport_protocol'],
                    'ip_version': connection['ip_version']
                }
                new_co = dict(sorted(new_co.items()))
                fco = frozenset(new_co.items())

            try:
                traces[fco].append(log)
            except KeyError:
                traces[fco] = [log]

    if 'ACK' in header['flags']:
        if len(header['flags']) > 1:
            header['seq'] = event.seq
            header['end_seq'] = event.end_seq
        header['ack'] = event.ack_seq

    header['win'] = event.win

    transport_type = 'packet_received' if event_type == 'rcv' else 'packet_sent'
    log = [timestamp,  'transport', transport_type, {'header': header}]
    events.append(log)

    try:
        traces[fco].append(log)
    except KeyError:
        traces[fco] = [log]
 
def process_send_event(cpu, data, size):
    process_event(cpu, data, size, 'snt')
    
def process_rcv_event(cpu, data, size):
    process_event(cpu, data, size, 'rcv')
   
print("Probe added")

signal.signal(signal.SIGINT, sigint_handler)
b["events"].open_perf_buffer(process_send_event)
b["rcv_events"].open_perf_buffer(process_rcv_event)

while True:
    b.perf_buffer_poll()
