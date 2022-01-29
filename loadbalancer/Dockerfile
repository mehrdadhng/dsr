FROM ubuntu:latest

RUN apt-get update && apt-get install iproute2 netcat tcpdump bpftrace -y
RUN apt-get install build-essential -y
RUN apt-get install kmod -y
RUN apt-get update
RUN apt-get install linux-tools-$(uname -r) -y
RUN apt-get install nano -y
RUN apt-get install python3 pip -y
RUN pip install numpy
RUN pip install matplotlib
RUN pip install scapy
RUN apt-get install curl -y
RUN apt-get install build-essential make -y
#RUN apt-get install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential make -y

COPY codes/ /xdp