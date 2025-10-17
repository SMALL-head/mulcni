package redirect

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"unsafe"

	"github.com/SMALL-head/mulcni/utils/tctools"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/sirupsen/logrus"
)

var (
	perfReaderRecordCh chan perf.Record
)

func init() {
	perfReaderRecordCh = make(chan perf.Record, 100)
}

func DropIPProg(ctx context.Context, ifaceName string) {
	var obj redirectObjects
	if err := loadRedirectObjects(&obj, nil); err != nil {
		logrus.Fatalf("Failed to load redirect objects: %v", err)
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		logrus.Fatalf("Failed to get interface %s: %v", ifaceName, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   obj.XdpDropIp,
		Interface: iface.Index,
	})
	if err != nil {
		logrus.Fatalf("Failed to attach XDP program: %v", err)
	}
	defer l.Close()
	logrus.Infof("XDP program attached to interface %s", ifaceName)

	for {
		select {
		case <-ctx.Done():
			logrus.Printf("🔴 Stopping DropIPProg() on iface: %s...", ifaceName)
			return
		}
	}
}

func RedirectProg(ctx context.Context, ifaceName string) {
	var obj *redirectObjects
	if err := loadRedirectObjects(&obj, nil); err != nil {
		logrus.Fatalf("Failed to load redirect objects: %v", err)
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		logrus.Fatalf("Failed to get interface %s: %v", ifaceName, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   obj.XdpAnalyse,
		Interface: iface.Index,
	})
	if err != nil {
		logrus.Fatalf("Failed to attach XDP program: %v", err)
	}
	defer l.Close()
	logrus.Infof("XDP program attached to interface %s", ifaceName)

	// 创建event perf监听器
	perfReader, err := perf.NewReader(obj.Events, os.Getpagesize())
	if err != nil {
		logrus.Fatalf("Failed to create perf reader: %v", err)
	}
	defer perfReader.Close()
	up := true
	go func() {
		for up {
			record, err := perfReader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					break
				}
				logrus.Errorf("reading record from perf reader, err = %v", err)
				continue
			}

			perfReaderRecordCh <- record
		}
		logrus.Infof("shutdown redirect Prog on iface %s goroutine from ctx", ifaceName)
	}()

	for {
		select {
		case <-ctx.Done():
			logrus.Printf("🔴 Stopping RedirectRrog() on iface: %s...", ifaceName)
			up = false
			return
		case record := <-perfReaderRecordCh:
			printEvent(record)
		}
	}
}

func TCIngressProc(ctx context.Context, ifaceName string) error {
	var obj redirectObjects
	if err := loadRedirectObjects(&obj, nil); err != nil {
		logrus.Fatalf("Failed to load redirect objects: %v", err)
	}
	defer obj.Close()
	// iface, err := net.InterfaceByName(ifaceName)
	// if err != nil {
	// 	logrus.Fatalf("Failed to get interface %s: %v", ifaceName, err)
	// }

	if err := tctools.AttachIngressBPFToIface(ifaceName, "/root/mulcni/pkg/ebpfProc/tc/tc.o", "classifier/redirect"); err != nil {
		logrus.Errorf("Failed to attach BPF to iface: %v", err)
		return err
	}

	defer tctools.DeleteIngressBPFFromIface(ifaceName)

	// l, err := link.AttachTCX(link.TCXOptions{
	// 	Program:   obj.TcIngressRedirect,
	// 	Interface: iface.Index,
	// 	Attach:    ebpf.AttachTCXIngress,
	// })
	// if err != nil {
	// 	logrus.Fatalf("Failed to attach TC program: %v", err)
	// }
	// defer l.Close()

	logrus.Infof("tc program attached to interface %s", ifaceName)

	// 阻塞一下，否则defer会立马执行，这里等待程序结束之后再执行defer
	for range ctx.Done() {
		logrus.Printf("🔴 Stopping TCIngressProc() on iface: %s...", ifaceName)
		return nil
	}
	return nil
}

func printEvent(record perf.Record) {
	var event redirectEvent
	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
		logrus.Printf("parsing perf event: %s", err)
		return
	}
	// event.Src = net.IPv4(event.Src[0], event.Src[1], event.Src[2], event.Src[3])
	// event.Dst = net.IPv4(event.Dst[0], event.Dst[1], event.Dst[2], event.Dst[3])
	logrus.Infof("[redirect] - get event info, src = %d, dst = %d", event.Src, event.Dst)
}

type TestKey struct {
	A uint32
}

type TestValue struct {
	B uint32
}

func MountMap(mapName string, pinPath string) *ebpf.Map {
	m, err := ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Name:       mapName,
		Pinning:    ebpf.PinByName, // 自动pin了
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(uint32(0))),
		ValueSize:  uint32(unsafe.Sizeof(uint32(0))),
		MaxEntries: 4096,
	}, ebpf.MapOptions{
		PinPath: pinPath,
	})
	if err != nil {
		logrus.Fatalf("Failed to create map: %v", err)
	}
	key := uint32(1)
	value := uint32(2)
	err = m.Put(key, value)
	if err != nil {
		logrus.Errorf("Failed to put value into map: %v", err)
	}

	return m
}

func AddItemToMap(m *ebpf.Map, key uint32, value uint32) error {
	err := m.Put(key, value)
	if err != nil {
		logrus.Errorf("Failed to put value into map: %v", err)
		return err
	}
	return nil
}
