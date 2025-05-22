package tctools_test

import (
	"testing"

	"github.com/SMALL-head/mulcni/utils/tctools"
)

func TestAttachBPF(t *testing.T) {
	ifaceName := "h-ns2"
	bpfFilePath := "/root/mulcni/pkg/ebpfProc/redirect/redirect.o"

	err := tctools.AttachIngressBPFToIface(ifaceName, bpfFilePath)
	if err != nil {
		t.Fatalf("Failed to attach BPF to iface: %v", err)
	}
}
