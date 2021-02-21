#! /bin/sh -e

KERNEL_SRC="${PWD}/../../mptcp_net-next"
MNT_POINT="/mnt"

docker run -it --privileged -v "${KERNEL_SRC}":"${MNT_POINT}" -e SRC="${MNT_POINT}" --device=/dev/kvm --device=/dev/net/tun -v /sys/fs/cgroup:/sys/fs/cgroup:rw --cap-add=NET_ADMIN --cap-add=SYS_ADMIN -e VM_IP="${VM_IP}" -e SERVER_IP="${SERVER_IP}" -e CONTAINER_NAME="${CONTAINER_NAME}" --rm --name "${CONTAINER_NAME}" virtme
