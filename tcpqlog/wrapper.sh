#! /bin/sh -e

KERNEL_SRC="${PWD}/mptcp_net-next"
MNT_POINT="/kernel_sources"

# Compile the mptcp helper tools
make -C mptcp-tools/use_mptcp/

# Build the container
docker build -t virtme -f virtme.dockerfile .

# Run the container 
docker run \
        -it --privileged --rm --name "${CONTAINER_NAME}" \
        --device=/dev/kvm --device=/dev/net/tun \
        --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
        -e SRC="${MNT_POINT}" \
        -e VM_IP="${VM_IP}" \
        -e SERVER_IP="${SERVER_IP}" \
        -e CONTAINER_NAME="${CONTAINER_NAME}" \
        -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
        -v "${KERNEL_SRC}":"${MNT_POINT}" \
        -v "${PWD}/output/${CONTAINER_NAME}":/mnt \
        -v "${PWD}/mptcp-tools":/mptcp-tools \
        virtme
