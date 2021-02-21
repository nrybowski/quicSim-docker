FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive
ARG LD_LIBRARY_PATH=/usr/local/lib
ARG PYTHONPATH=/usr/local/lib/python3/dist-packages/

RUN apt-get update && apt-get install -y \
	lsb-release wget software-properties-common bison flex cmake git python \
	build-essential libelf-dev libedit-dev libclang-11-dev netperf arping iperf3 \
	python3 python3-pip wget

RUN wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 11

RUN apt-get install libclang-11-dev

RUN git clone https://github.com/iovisor/bcc.git && mkdir bcc/build; cd bcc/build \
	&& cmake .. && make -j$(nproc) && make -j$(nproc) install && \
	cmake -DPYTHON_CMD=python3 .. && cd src/python/ && make -j$(nproc) && \
	make -j$(nproc) install && cd ../..
