# TCPQLOG

This folder contains a prototype of QLOG logs generator for TCP and MPTCP connections.

It leverages eBPF [1], function tracing using kprobes [2] on the Linux kernel and BCC [3].

## Table of content
1. [Requirements](#requirements)
2. [Repository content](#repository-content)
3. [Prototype usage](#prototype-usage)
4. [Test setup](#test-setup)
5. [QLOG format](#qlog-format)
	1. [Events](#events)
	2. [Others](#others)
	3. [Illustration](#illustration)
6. [Prototype description](#prototype-description)
	1. [Traced functions](#traced-functions)
	2. [Limitations](#limitations)
7. [Future works](#future-works)
8. [References](#references)

## Requirements 

A working [Docker](https://www.docker.com/) installation is required.

## Repository content
```
.
├── mptcp_net-next	# (Git submodule) Linux kernel implementation of MPTCPv1 (at tag export/20210218T061505).
├── mptcp-tools		# (Git submodule) Helper tool to enable MPTCPv1 connections (at hash d433f3846e6fae33a3e564494e6148cd8d3b3418).
├── output
│   ├── client		# Folder containing client QLOG outputs.
│   ├── server		# Folder containing server QLOG outputs.
│   └── tcpdump.log	# Tcpdump trace of the traffic between the client and the server.
├── README.md
├── tcp.py 		# eBPF programs and user-space script to gather the data and format the logs.
├── virtme.dockerfile	# A dockerfile which installs BCC, virtme and executes the eBPF programs in a VM running the MPTCPv1 kernel implementation.
├── virtme_run.sh	# A script preparing the test environment and running the tests into the container.
└── wrapper.sh		# A helper script launching the whole prototype.
```

## Prototype usage

Two terminals are required to execute this project.

Terminal 1 runs the server: 

```
CONTAINER_NAME=server VM_IP=172.17.0.10 ./wrapper.sh
```

Terminal 2 executes the client:

```
CONTAINER_NAME=client VM_IP=172.17.0.30 SERVER_IP=172.17.0.10 ./wrapper.sh
```

## Test setup

```
|-----------------------------------------------|    |-----------------------------------------------|
| Client container                              |    | Server container                              |
|---------------------------|                   |    |                   |---------------------------|
|| Virtme VM (MPTCP kernel) |                   |    |                   | Virtme VM (MPTCP kernel) ||
||--------------------------|                   |    |                   |--------------------------||
|| curl 172.17.0.10:8000    |                   |    |                   | python3 -m http.server   ||
|| python3 tcp.py &         |                   |    |                   | python3 tcp.py &         ||
||--------------------------|                   |    |                   |--------------------------||
|| eth0 (172.17.0.30)       | tap0 \            |    |            / tap0 | eth0 (172.17.0.10)       || 
|| eth1 (172.17.1.31)       | tap1 - br0 - eth0 | -- | eth0 - br0 - tap1 | eth1 (172.17.1.11)       ||
|| eth2 (172.17.2.32)       | tap2 /            |    |            \ tap2 | eth2 (172.17.2.12)       ||
|---------------------------|-------------------|    |-------------------|--------------------------||
```

The previous figure illustrates the test setup.
The client and the server are configured the same way, only the IPv4 addresses change.

Each docker container contains an MPTCP kernel running in a QEMU-KVM virtual machine setup by the virtme tool [4].
Three tap-tun interfaces are created for the VM and bridged on the container's interface.

On the server-side, a simple HTTP server is launched as well as the QLOG logger prototype.
The client simply makes a GET request on this server with the QLOG logger prototype running in background.
All the commands launched in the VMs are wrapped with the [`use_mptcp.sh` script](mptcp-tools/use_mptcp/use_mptcp.sh) provided by the `mptcp-tools`submodule.
This forces all the TCP connections to be MPTCP ones by hijacking the socket library call.

This whole setup is heavily inspired from [5].

## QLOG format

The proposed format is still incomplete but should be a correct basis for future work.
It is dumped into JSON format.

The prototype collects only lists of events which respect the semantic defined in [6].
Complete real example traces are available [in the output folder](output)

### Events

An event is an array containing:
1. a timestamp
2. a category and an event
3. the data of the event
4. a group id

For example, the initialization of a TCP connection on the client-side is logged as following:
```
[13237874729, 'connectivity', 'connection_started', {'dst_ip': '172.17.0.10', 'dst_port': 8000, 'ip_version': '4', 'src_ip': '172.17.0.30', 'src_port': 50952, 'transport_protocol': 'TCP'}, '2ba0ebea0ce9f6b9f6d1a6098cbeaa9e']
```
The data here is the 4-tuple of TCP with some additional informations on the transport protocol and the IP version.

The group id is the MD5 hash of the 4-tuple [source ip, source port, destination ip, destination port].
```
>>> hashlib.md5(json.dumps(['172.17.0.30', 50952, '172.17.0.10', 8000]).encode('utf8')).hexdigest()
'2ba0ebea0ce9f6b9f6d1a6098cbeaa9e'
```

It is used to identify the connection to which an event belongs to.

The hash of the 4-tuple is preferred over the whole connection data, which include the IP family and the transport protocol detail, to save some space in the traces.

#### `connectivity`

This event family logs connection related data.

##### `connection_started`

This event logs the creation of a new connection.
The data field is defined as following:
```
{
	'dst_ip': IPAddress,
	'dst_port': uint32, 
	'src_ip': IPAddress,
	'src_port': uint32
	'ip_version': '4' | '6',
	'protocol': 'TCP' | 'MPTCP'
}
```

This format is compliant with the [`connectivity:connection_started` data format of QUIC](https://quicwg.org/qlog/draft-ietf-quic-qlog-quic-events.html#name-packet_received).

##### `subflow_connection_started`

This event indicates that a new MPTCP subflow is created.

The data format is the same as for the previous `connection_started` event.

However, this event extends the event array with an additional group id.

The first one still identifies the current connection while the second one identifies the parent MPTCP connection. 

This allows to the MPTCP subflows to link themselves with their parent connection.

The rest of the connection events only contains the subflow group id.

#### `transport`

This event family logs transport related data.

##### `packet_sent`

The data field is defined as following:
```
{
	'header': PacketHeader
}
```

This format is compliant with the [`transport:packet_sent` data format of QUIC](https://quicwg.org/qlog/draft-ietf-quic-qlog-quic-events.html#name-packet_sent).

##### `packet_received`

The data field is defined as following:
```
{
	'header': PacketHeader
}
```

This format is compliant with the [`transport:packet_received` data format of QUIC](https://quicwg.org/qlog/draft-ietf-quic-qlog-quic-events.html#name-packet_received).

### Others

#### `IPAddress`

```
IPAddress: string
```

This format is compliant with [the one defined for QUIC](https://quicwg.org/qlog/draft-ietf-quic-qlog-quic-events.html#name-ipaddress).

#### `PacketHeader`

This format is **not** compliant with the [QUIC `PacketHeader` format](https://quicwg.org/qlog/draft-ietf-quic-qlog-quic-events.html#name-packetheader) since it is protocol dependant.

```
{
	'flags': Array<TCPFlag>,		// TCP flags
	'seq'?: uint64 | [uint64, uint64],	// TCP sequence number 
	'ack'?: uint64,				// TCP acknowledgment number
	'win'?: uint64 				// TCP receive window
}
```

#### `TCPFlag`

```
TCPFlag: 'SYN' | 'ACK' | 'RST' | 'PSH'
```

### Illustration

Here are the client-side TCP handshakes logged for a 3-subflows MPTCP connection.
We see that each subflow is identified by its group id and that it references its parent MPTCP connection.

```
[13237874729, 'connectivity', 'connection_started', {'dst_ip': '172.17.0.10', 'dst_port': 8000, 'ip_version': '4', 'src_ip': '172.17.0.30', 'src_port': 50952, 'transport_protocol': 'TCP'}, '2ba0ebea0ce9f6b9f6d1a6098cbeaa9e']
[13237874729, 'transport', 'packet_sent', {'header': {'flags': ['SYN'], 'seq': 182139483, 'win': 0}}, '2ba0ebea0ce9f6b9f6d1a6098cbeaa9e']
[13238791973, 'transport', 'packet_received', {'header': {'flags': ['SYN', 'ACK'], 'seq': 2079434258, 'ack': 182139484, 'win': 65160}}, '2ba0ebea0ce9f6b9f6d1a6098cbeaa9e']
[13238839345, 'transport', 'packet_sent', {'header': {'flags': ['ACK'], 'ack': 1, 'win': 0}}, '2ba0ebea0ce9f6b9f6d1a6098cbeaa9e']

[...]

[13241118215, 'connectivity', 'subflow_connection_started', {'dst_ip': '172.17.0.10', 'dst_port': 8000, 'ip_version': '4', 'src_ip': '172.17.1.31', 'src_port': 48615, 'transport_protocol': 'TCP'}, 'cdbdf00b802e84969f4dfcce3c43f37e', '2ba0ebea0ce9f6b9f6d1a6098cbeaa9e']
[13241118215, 'transport', 'packet_sent', {'header': {'flags': ['SYN'], 'seq': 1873275315, 'win': 0}}, 'cdbdf00b802e84969f4dfcce3c43f37e']
[13243053215, 'transport', 'packet_received', {'header': {'flags': ['SYN', 'ACK'], 'seq': 852837744, 'ack': 1873275316, 'win': 65160}}, 'cdbdf00b802e84969f4dfcce3c43f37e']
[13243088040, 'transport', 'packet_sent', {'header': {'flags': ['ACK'], 'ack': 1, 'win': 0}}, 'cdbdf00b802e84969f4dfcce3c43f37e']

[...]

[13243425262, 'connectivity', 'subflow_connection_started', {'dst_ip': '172.17.0.10', 'dst_port': 8000, 'ip_version': '4', 'src_ip': '172.17.2.32', 'src_port': 55137, 'transport_protocol': 'TCP'}, 'a90078718fcc22e98d79a3c56cb69d65', '2ba0ebea0ce9f6b9f6d1a6098cbeaa9e']
[13243425262, 'transport', 'packet_sent', {'header': {'flags': ['SYN'], 'seq': 863497603, 'win': 0}}, 'a90078718fcc22e98d79a3c56cb69d65']
[13244046390, 'transport', 'packet_received', {'header': {'flags': ['SYN', 'ACK'], 'seq': 1201300528, 'ack': 863497604, 'win': 65160}}, 'a90078718fcc22e98d79a3c56cb69d65']
[13244075302, 'transport', 'packet_sent', {'header': {'flags': ['ACK'], 'ack': 1, 'win': 0}}, 'a90078718fcc22e98d79a3c56cb69d65']
```

## Prototype description

The prototype collects network level events by tracing kernel functions calls.
This is achieved by attaching eBPF programs to kernel probes (kprobes) [2].
Such programs are triggered upon execution of the probed kernel functions.
They have access to the arguments of the functions and send custom data to the user-space through perf events and perf buffers.

### Traced functions

Here is the list of the functions traced to output the current QLOG format:
- `__tcp_transmit_skb`: transmits TCP packets. We see SYN, ACK, PSH, etc packets sent with this function. 
- `tcp_make_synack`: builds SYN-ACK packets. We track this function since SYN-ACKs do not appear when tracing `__tcp_transmit_skb`.
- `tcp_conn_request`: listen for incoming connection. It is triggered upon SYN reception.
- `tcp_ack`: routine handling incoming ACK.
- `tcp_reset`: routine handling incoming RST.

### Limitations

#### Reachable data through kprobes

The eBPF program attached to a kprobe is executed when the kernel enters the probed function.
This means that some data might not be defined yet when the eBPF program is executed.

Also, attaching to a kretprobe (a probe triggered upon function return) does not help since eBPF only lets access to the return value of the probed function.
One could try to put the socket pointer address in a BPF map at a kprobe and then explore the socket's fields in a kretprobe.
But currently, the eBPF verifier does not allow storing socket pointers in maps for such usage.

This leads to some limitations in terms of readable fields.
Those are described in the next points.

##### MPTCP token

MPTCP exposes a unique token for each MPTCP connection.
It is embedded in the subflows packets in order to identify their parent connection.
Currently, I did not found any suitable place to extract this token.

For instance, one could consider tracking [`mptcp_subflow_create_socket`](https://elixir.bootlin.com/linux/v5.12/source/net/mptcp/subflow.c#L1357) to detect the creation of a new subflow socket.
But at this kprobe, the socket is the parent one and the child subflow does not exists.

Another place where one could extract the token is in the `__tcp_transmit_skb` routine.
By converting the input `struct sock` to a `struct tcp_sock`, one could read the [`is_mptcp` flag](https://elixir.bootlin.com/linux/v5.12/source/include/linux/tcp.h#L394) which indicates whether the current socket is an MPTCP one.
If it is the case, the token should be retrievable in the `struct mptcp_subflow_context` cast of the socket. 
However, the value we get at this point is different from the one read in tcpdump.

For this reason, the 4-tuple of the parent connection is extracted rather than the token (See line 147 of [tcp.py](tcp.py)).

##### Reception window of sent packets

The receive window of the sent packets is not yet computed at the entrance of `__tcp_transmit_skb`.
It takes place [ater in the function](https://elixir.bootlin.com/linux/v5.12/source/net/ipv4/tcp_output.c#L1350).

#### IPv4 only

While the majority of the traced kernel functions are used for both IPv4 and IPv6 (`__tcp_transmit_skb`, ...) some of them are protocol specific.
For instance, `tcp_v{4, 6}_send_reset` is protocol specific and requires tracing two functions.
An alternative for those specific functions could be the [tracepoint associated to this event](https://elixir.bootlin.com/linux/v5.12/source/include/trace/events/tcp.h#L109).

#### No `connection_closed` events

The end of the connections is currently not logged.

#### Pure RST packets

The logging of "direct" RST packets (e.g. when initiating a TCP connection on a closed port) might be broken.
The `tcp_v4_send_reset` function was traced to that end at some point.

## Future works

### Better kprobes

The currently probed functions are maybe not the best ones for the kind of data we are looking for, regarding the limitation we just mentioned.
Here are some propositions:
- [`bpf_skops_write_hdr_opt`](https://elixir.bootlin.com/linux/v5.12/source/net/ipv4/tcp_output.c#L534): This function is called at the end of both [`__tcp_transmit_skb`](https://elixir.bootlin.com/linux/v5.12/source/net/ipv4/tcp_output.c#L1372) and [`tcp_make_synacks`](https://elixir.bootlin.com/linux/v5.12/source/net/ipv4/tcp_output.c#L3611).
Tracing this function could solve two problems at once.
First, only one function is probed rather than two.
Second, it solves the issue of the 0 receive window since its computation takes place before this function call.
That being said, this function is also an [anchor for the SOCKOPS eBPF programs](https://elixir.bootlin.com/linux/v5.12/source/net/ipv4/tcp_output.c#L566).
One could consider to use this kind of eBPF programs rather than kprobes tracing.
However, they do not support MPTCP specific manipulations yet.
- [`tcp_connect`](https://elixir.bootlin.com/linux/v5.12/source/net/ipv4/tcp_output.c#L3825) and [`__mptcp_subflow_connect`](https://elixir.bootlin.com/linux/v5.12/source/net/mptcp/subflow.c#L1232): Detect the initiation of a new outgoing (MP)TCP connection.
Currently, the QLOG `connectivity:connection_started` event is derived from the first SYN packet seen in `__tcp_transmit_skb`.
It is more logical to trace the real connection initialization function. 
- [`tcp_close`](https://elixir.bootlin.com/linux/v5.12/source/net/ipv4/tcp.c#L2864): Detect and log the connection closing. 

### Integrating congestion window data

A [previous work](../tcpebpf/bccscripts/) already implemented such kind of logic.
Merging the two works might be interesting.

### Supporting SACKs

Currently, none of the interfaces has been tuned to drop some packets.
Hence, no SACKs are generated and the prototype do not handle such data.

### Replace perf buffer by ring buffers

The current perf buffers used suffer from ordering issues.
The events arriving in the user-space are not in the same order as their appearance in the kernel.
This requires an additional sorting step in user-space post-process.

This issue could be solved by using the newer ring buffers as explained by Nakryiko [7].

## References

[1] https://ebpf.io/

[2] https://www.kernel.org/doc/html/latest/trace/kprobes.html

[3] https://github.com/iovisor/bcc

[4] https://github.com/amluto/virtme

[5] https://github.com/multipath-tcp/mptcp_net-next/blob/scripts/bpf/examples/README.md

[6] https://quicwg.org/qlog/draft-ietf-quic-qlog-main-schema.html#name-field-name-semantics

[7] https://nakryiko.com/posts/bpf-ringbuf/
