#! /bin/bash -e

CUR_DIR="${PWD}"
cd "${SRC}"
# install new kernel modules for BCC
kconfig=(-e BPF_SYSCALL -d CGROUP_BPF -d BPF_PRELOAD -d XDP_SOCKETS -d BPF_KPROBE_OVERRIDE \
        -d KPROBE_EVENT_GEN_TEST -e CONFIG_KALLSYMS_ALL)
#virtme-configkernel --defconfig
#echo | ./scripts/config "${kconfig[@]}"
#make -j"$(nproc)"
#make -j"$(nproc)" > /dev/null 2>&1 
make -j"$(nproc)" headers_install > /dev/null 2>&1 
make -j"$(nproc)" modules_install > /dev/null 2>&1 
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
sk.bind(('${VM_IP}', 5000))
sk.listen()

while True:
    conn, addr = sk.accept()

def sigint_handler(_sig, _frame):
    sys.exit(0)

signal.signal(signal.SIGINT, sigint_handler)
EOF

elif [[ "${CONTAINER_NAME}" == "client" ]]
then

cat <<EOF > script.py
import socket

for i in range(1,3):
    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.connect(('${SERVER_IP}', 5000))
    sk.send(b'test'*i)
    sk.close()
EOF

fi

cat <<EOF > run.sh
#! /usr/bin/expect -f

set timeout 1500

# start KVM
spawn virtme-run --kdir ${SRC}  --rodir ${SRC}  --rwdir /mnt --rodir /lib/modules --qemu-opts -m 700M -enable-kvm -device e1000,netdev=net0,mac=52:54:01:12:34:${END} -netdev tap,id=net0,br=br0

# wait for KVM entire boot
expect "virtme-init: console is ttyS0\r"

# KVM side network setup
send -- "ip a add ${VM_IP}/16 dev eth0\r"
send -- "ip l set dev eth0 up\r"
send -- "ip r add default via ${GATEWAY} dev eth0\r"

# launch scripts
send -- "cd /wd\r"
send -- "set -e\r"
#send -- "./script.sh &\r"
send -- "python3 tcp.py &\r"

# wait for BPF programs injection
expect "Probe added"

send -- "python3 script.py &\r"

send -- "sleep 10\r"
send -- "pkill -2 python3\r"
send -- "cat /sys/kernel/debug/tracing/trace\r"

# kill KVM
send -- "/usr/lib/klibc/bin/poweroff\r"

expect eof
EOF
chmod +x run.sh

./run.sh
