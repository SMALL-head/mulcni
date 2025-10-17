package xdp

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go  -target amd64 xdp xdp.bpf.c -- -I ../include/
