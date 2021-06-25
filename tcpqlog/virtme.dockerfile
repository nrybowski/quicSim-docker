# Install BCC from source in ubuntu:20.04
FROM ubuntu:20.04 as bcc

ARG DEBIAN_FRONTEND=noninteractive
ARG LD_LIBRARY_PATH=/usr/local/lib
ARG PYTHONPATH=/usr/local/lib/python3/dist-packages/

# Install tools to build BCC sources
RUN apt-get update && apt-get install -y \
	lsb-release wget software-properties-common bison flex cmake git python \
	build-essential libelf-dev libedit-dev libclang-11-dev netperf arping iperf3 \
	python3 python3-pip wget

# Install LLVM11
RUN wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 11

RUN apt-get install libclang-11-dev

RUN git clone https://github.com/iovisor/bcc.git &&\
    mkdir bcc/build; cd bcc/build &&\
	cmake .. && make -j$(nproc) &&\
    make -j$(nproc) install &&\
	cmake -DPYTHON_CMD=python3 .. &&\
    cd src/python/ &&\
    make -j$(nproc) && \
	make -j$(nproc) install &&\
    cd ../..

# Install virtme and add tools from source to support MPTCP
FROM bcc

ARG DEBIAN_FRONTEND=noninteractive

WORKDIR /wd

RUN apt-get update && apt-get install -y git qemu-kvm python3-pip klibc-utils \
	rsync kmod libelf-dev bc iproute2 iputils-ping expect binutils-dev \
    libreadline-dev tcpdump curl libssl-dev

# Install virtme
RUN git clone https://github.com/ezequielgarcia/virtme.git &&\
    cd virtme &&\
	python3 ./setup.py install

# Shortcut to easily kill the virtme VM
RUN ln -s /usr/lib/klibc/bin/poweroff /bin

# Create a directory for the modules of the MPTCP kernel
RUN mkdir -pv /lib/modules/5.11.0-rc7+/

# Install tcpdump and iproute2 from source to support MPTCP
# See https://github.com/multipath-tcp/mptcp_net-next/blob/scripts/ci/Dockerfile.virtme.sh#L28
ENV LIBPCAP_GIT_URL="https://github.com/the-tcpdump-group/libpcap.git"
ENV LIBPCAP_GIT_SHA="libpcap-1.10.0"
ENV TCPDUMP_GIT_URL="https://github.com/the-tcpdump-group/tcpdump.git"
ENV TCPDUMP_GIT_SHA="tcpdump-4.99.0"

RUN cd /opt && \
    git clone "${LIBPCAP_GIT_URL}" libpcap && \
    git clone "${TCPDUMP_GIT_URL}" tcpdump && \
    cd libpcap && \
        git checkout "${LIBPCAP_GIT_SHA}" && \
        ./configure --prefix=/usr && \
        make -j"$(nproc)" -l"$(nproc)" && \
        make install && \
    cd ../tcpdump && \
        git checkout "${TCPDUMP_GIT_SHA}" && \
        ./configure --prefix=/usr && \
        make -j"$(nproc)" -l"$(nproc)" && \
        make install && \
	cd /wd

ENV IPROUTE2_GIT_URL="git://git.kernel.org/pub/scm/network/iproute2/iproute2.git"
ENV IPROUTE2_GIT_SHA="9c3be2c0eee01be7832b7900a8be798a19c659a5"
RUN cd /opt && \
    git clone "${IPROUTE2_GIT_URL}" iproute2 && \
    cd iproute2 && \
        git checkout "${IPROUTE2_GIT_SHA}" && \
        ./configure && \
        make -j"$(nproc)" -l"$(nproc)" && \
        make install

ARG SRC
COPY virtme_run.sh tcp.py ./
RUN chmod +x virtme_run.sh

CMD ["./virtme_run.sh"]
