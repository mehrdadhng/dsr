all: xdp_lb_kern.o xdp_server1_kern.o xdp_server2_kern.o xdp_server3_kern.o xdp_lb2_kern.o xdp_lb3_kern.o xdp_server4_kern.o

xdp_lb_kern.o: xdp_lb_kern.c 
	clang -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    -I../../libbpf/src \
		-I../../custom-headers \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -O2 -emit-llvm -c -o ${@:.o=.ll} $<
	llc -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

xdp_lb2_kern.o: xdp_lb2_kern.c 
	clang -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    -I../../libbpf/src \
		-I../../custom-headers \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -O2 -emit-llvm -c -o ${@:.o=.ll} $<
	llc -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

xdp_lb3_kern.o: xdp_lb3_kern.c 
	clang -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    -I../../libbpf/src \
		-I../../custom-headers \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -O2 -emit-llvm -c -o ${@:.o=.ll} $<
	llc -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

xdp_server1_kern.o: xdp_server1_kern.c 
	clang -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    -I../../libbpf/src \
		-I../../custom-headers \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -O2 -emit-llvm -c -o ${@:.o=.ll} $<
	llc -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

xdp_server2_kern.o: xdp_server2_kern.c 
	clang -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    -I../../libbpf/src \
		-I../../custom-headers \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -O2 -emit-llvm -c -o ${@:.o=.ll} $<
	llc -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

xdp_server3_kern.o: xdp_server3_kern.c 
	clang -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    -I../../libbpf/src \
		-I../../custom-headers \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -O2 -emit-llvm -c -o ${@:.o=.ll} $<
	llc -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

xdp_server4_kern.o: xdp_server4_kern.c 
	clang -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    -I../../libbpf/src \
		-I../../custom-headers \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -O2 -emit-llvm -c -o ${@:.o=.ll} $<
	llc -march=bpf -filetype=obj -o $@ ${@:.o=.ll}
load_balancer:
	bpftool net detach xdpgeneric dev eth0
	rm -f /sys/fs/bpf/xdp_lb
	bpftool prog load xdp_lb_kern.o /sys/fs/bpf/xdp_lb
	bpftool net attach xdpgeneric pinned /sys/fs/bpf/xdp_lb dev eth0
load_balancer2:
	bpftool net detach xdpgeneric dev eth0
	rm -f /sys/fs/bpf/xdp_lb
	bpftool prog load xdp_lb2_kern.o /sys/fs/bpf/xdp_lb
	bpftool net attach xdpgeneric pinned /sys/fs/bpf/xdp_lb dev eth0
load_balancer3:
	bpftool net detach xdpgeneric dev eth0
	rm -f /sys/fs/bpf/xdp_lb
	bpftool prog load xdp_lb3_kern.o /sys/fs/bpf/xdp_lb
	bpftool net attach xdpgeneric pinned /sys/fs/bpf/xdp_lb dev eth0
load_server1:
	bpftool net detach xdpgeneric dev eth0
	rm -f /sys/fs/bpf/xdp_server
	bpftool prog load xdp_server1_kern.o /sys/fs/bpf/xdp_server
	bpftool net attach xdpgeneric pinned /sys/fs/bpf/xdp_server dev eth0
load_server2:
	bpftool net detach xdpgeneric dev eth0
	rm -f /sys/fs/bpf/xdp_server
	bpftool prog load xdp_server2_kern.o /sys/fs/bpf/xdp_server
	bpftool net attach xdpgeneric pinned /sys/fs/bpf/xdp_server dev eth0
load_server3:
	bpftool net detach xdpgeneric dev eth0
	rm -f /sys/fs/bpf/xdp_server
	bpftool prog load xdp_server3_kern.o /sys/fs/bpf/xdp_server
	bpftool net attach xdpgeneric pinned /sys/fs/bpf/xdp_server dev eth0
load_server4:
	bpftool net detach xdpgeneric dev eth0
	rm -f /sys/fs/bpf/xdp_lb
	bpftool prog load xdp_server4_kern.o /sys/fs/bpf/xdp_lb
	bpftool net attach xdpgeneric pinned /sys/fs/bpf/xdp_lb dev eth0
clean:
	rm -f *.o
	rm -f *.ll