package redirect

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go  -target amd64 redirect redirect.bpf.c -- -I/root/mulcni/pkg/ebpfProc/include/
