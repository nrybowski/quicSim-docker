# TCPQLOG

This folder contains a prototype of QLOG logs generator using eBPF on the Linux kernel.

The Linux kernel sources are expected at `"${PWD}/../../"`, [`mptcp_net-next`](https://github.com/multipath-tcp/mptcp_net-next) has been used.

A working installation of Docker is required.

## Files
- `tcp.py` : BPF programs and User-space script to gather the data and format the logs.
- `bcc.dockerfile` : A dockerfile to install the latest version of BCC using LLVM11.
- `virtme.dockerfile` : A dockerfile to install virtme and run the BPF programs in a specific kernel version.
- `virtme_run.sh` : The script to prepare the environment and run the test into the container.
- `generate.sh` : A helper script to build the containers.
- `wrapper.sh` : A helper script to run the containers.

## Run

Two terminals are required to execute this project.
In terminal 1, run `CONTAINER_NAME=server VM_IP=172.17.0.11 ./wrapper.sh` to execute the server.
In terminal 2, run `CONTAINER_NAME=client VM_IP=172.17.0.30 SERVER_IP=172.17.0.11 ./wrapper.sh` to execute the client.
