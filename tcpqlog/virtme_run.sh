#! /bin/bash -e

CUR_DIR="${PWD}"
cd "${SRC}"
# install new kernel modules for BCC
kconfig=(-e BPF_SYSCALL -d CGROUP_BPF -d BPF_PRELOAD -d XDP_SOCKETS -d BPF_KPROBE_OVERRIDE \
        -d KPROBE_EVENT_GEN_TEST -e CONFIG_KALLSYMS_ALL -e NET_SCH_NETEM)
#virtme-configkernel --defconfig
#echo | ./scripts/config "${kconfig[@]}"
#make -j"$(nproc)"
#make -j"$(nproc)" > /dev/null 2>&1 
make -j"$(nproc)" headers_install > /dev/null 2>&1 
make -j"$(nproc)" modules_install > /dev/null 2>&1 
make -j"$(nproc)" -C tools/bpf/bpftool install
cd "${CUR_DIR}"

# get container IP to configure container connectivity
IP=$(ip a | grep 'inet 172'| sed -e 's/[ ]*inet //g' -e 's/ [ .0-9a-z]*//g')
GATEWAY=$(echo "${IP}" | sed -e 's/\/[0-9]*//g')
END=$(echo "${VM_IP}" | sed -e 's/[0-9]*\.//g')

# setup container networking to make the KVM reachable from outside
ip l add dev br0 type bridge
ip l set dev eth0 master br0
ip a del "${IP}" dev eth0
ip a add "${IP}" dev br0
ip l set dev br0 up
ip r add default via 172.17.0.1 dev br0

if [[ "${CONTAINER_NAME}" == "server" ]]
then

cat <<EOF > script.py
import socket
import signal

sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#sk.bind(('${VM_IP}', 5000))
sk.bind(('', 5000))
sk.listen()

while True:
    conn, addr = sk.accept()
    with conn:
        print('Connected by', addr)
        while True:
            data = conn.recv(4096)
            if not data: break
        print('End1')
    print('End2')

def sigint_handler(_sig, _frame):
    sys.exit(0)

signal.signal(signal.SIGINT, sigint_handler)
EOF

elif [[ "${CONTAINER_NAME}" == "client" ]]
then

cat <<EOF > script.py
import socket
import time

for i in range(1,2):
    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.connect(('${SERVER_IP}', 5000))
    sk.sendall(b'A'*pow(10, 6))
    sk.shutdown(socket.SHUT_WR)
    sk.close()
    time.sleep(20)
    print('Client end')
EOF

fi
MAC0="52:54:01:12:34"
MAC1="${MAC0}:${END}"
MAC2="${MAC0}:$((${END}+1))"
MAC3="${MAC0}:$((${END}+2))"
IP="/usr/sbin/ip"

cat <<EOF > run.sh
#! /usr/bin/expect -f

set timeout 1500

# start KVM
spawn virtme-run --kdir ${SRC}  --rodir /mptcp-tools --rodir ${SRC}  --rwdir /mnt --rodir /lib/modules --qemu-opts -m 700M -enable-kvm -device e1000,netdev=net0,mac=${MAC1} -netdev tap,id=net0,br=br0 -device e1000,netdev=net1,mac=${MAC2} -netdev tap,id=net1,br=br0 -device e1000,netdev=net2,mac=${MAC3} -netdev tap,id=net2,br=br0

# wait for KVM entire boot
expect "virtme-init: console is ttyS0\r"

# KVM side network setup
send -- "${IP} l set dev eth0 up\r"
send -- "${IP} l set dev eth1 up\r"
send -- "${IP} l set dev eth2 up\r"

send -- "${IP} a add ${VM_IP}/16 dev eth0\r"
send -- "${IP} a add 172.17.1.$((${END} + 1))/16 dev eth1\r"
send -- "${IP} a add 172.17.2.$((${END} + 2))/16 dev eth2\r"

send -- "${IP} mptcp endpoint flush\r"
send -- "${IP} mptcp limits set add_addr_accepted 8 subflows 8\r"

if { "${CONTAINER_NAME}" == "client" } {
    #send -- "tc qdisc add dev eth0 root netem delay 1500ms 0\r"
    #send -- "${IP} mptcp endpoint add ${VM_IP} subflow\r"
    send -- "${IP} mptcp endpoint add 172.17.1.$((${END} + 1)) subflow\r"
    send -- "${IP} mptcp endpoint add 172.17.2.$((${END} + 2)) subflow\r"
}

send -- "${IP} r add default via ${GATEWAY} dev eth0\r"

send -- "sleep 2\r"

# launch scripts
send -- "cd /wd\r"
send -- "set -e\r"

# wait for BPF programs injection
send -- "python3 tcp.py &\r"
expect "Probe added"

if { "${CONTAINER_NAME}" == "client" } {
    #send -- "/mptcp-tools/use_mptcp/use_mptcp.sh python3 script.py &\r"
    send -- "/mptcp-tools/use_mptcp/use_mptcp.sh curl ${SERVER_IP}:8000 > /dev/null 2>&1 \r"
} elseif { "${CONTAINER_NAME}" == "server" } {
    send -- "/mptcp-tools/use_mptcp/use_mptcp.sh python3 -m http.server & \r"
    #send -- "python3 -m http.server & \r"
}
#send -- "python3 script.py &\r"

#send -- "sleep 10\r"
#send -- "pkill -2 python3\r"

# kill KVM
if { "${CONTAINER_NAME}" == "client" } {
    #expect "Client end"
    #send -- "cat /sys/kernel/debug/tracing/trace\r"
} elseif { "${CONTAINER_NAME}" == "server" } {
    expect "172.17.0."
}

send -- "pkill -2 python3\r"
expect "Dump end"
send -- "cat /sys/kernel/debug/tracing/trace\r"
send -- "/usr/lib/klibc/bin/poweroff\r"

expect eof
EOF
chmod +x run.sh

./run.sh
