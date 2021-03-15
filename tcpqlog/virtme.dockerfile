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

ARG SRC
COPY virtme_run.sh tcp.py ./
RUN chmod +x virtme_run.sh

CMD ["./virtme_run.sh"]
