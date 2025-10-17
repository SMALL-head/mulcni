package tctools_test

import (
	"testing"

	"github.com/SMALL-head/mulcni/utils/tctools"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
}

func TestAttachBPF(t *testing.T) {
	ifaceName := "h-ns2"
	bpfFilePath := "/root/mulcni/pkg/ebpfProc/redirect/redirect.o"

	err := tctools.AttachIngressBPFToIface(ifaceName, bpfFilePath, "classifier/redirect")
	if err != nil {
		t.Fatalf("Failed to attach BPF to iface: %v", err)
	}
}

func TestExistsQdisc(t *testing.T) {
	ifaceName := "h-ns2"
	exists := tctools.ExistsQdisc(ifaceName)
	require.Equal(t, true, exists)
}
