FROM bcc

ARG DEBIAN_FRONTEND=noninteractive

WORKDIR /wd

RUN apt-get update && apt-get install -y git qemu-kvm python3-pip klibc-utils \
	rsync kmod libelf-dev bc iproute2 iputils-ping expect binutils-dev libreadline-dev

RUN git clone https://github.com/ezequielgarcia/virtme.git && cd virtme && \
	python3 ./setup.py install

RUN ln -s /usr/lib/klibc/bin/poweroff /bin
RUN mkdir -pv /lib/modules/5.11.0-rc7+/

RUN apt-get install tcpdump

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

RUN apt-get update && apt-get install -y curl

ARG SRC
COPY virtme_run.sh tcp.py ./
RUN chmod +x virtme_run.sh

CMD ["./virtme_run.sh"]
