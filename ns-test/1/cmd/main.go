package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/SMALL-head/mulcni/pkg/ebpfProc/redirect"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

func mountMap() {
	m := redirect.MountMap("testmap", "/sys/fs/bpf/tc/globals")
	defer func() {
		m.Unpin()
		m.Close()
	}()

	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, os.Interrupt, syscall.SIGTERM)

	<-stopCh

}

func origin() {
	ctxWithCancel, cancel := context.WithCancel(context.Background())
	eg, _ := errgroup.WithContext(context.TODO()) // 此处我用不到context

	// eg.Go(func() error {
	// 	// vethc2f35b2
	// 	redirect.DropIPProg(ctxWithCancel, "vethc2f35b2") // Replace with your interface name
	// 	return nil
	// })

	m := redirect.MountMap("testmap", "/sys/fs/bpf/xdp/globals")

	defer func() {
		m.Unpin()
		m.Close()
	}()

	eg.Go(func() error {
		return redirect.TCIngressProc(ctxWithCancel, "h-ns1") // Replace with your interface name
	})

	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, os.Interrupt, syscall.SIGTERM)

	<-stopCh
	// 收到停止信号后一方面通知errgroup执行清理操作，另一方面等待errgroup中的所有goroutine完成
	logrus.Info("Received stop signal, waiting for all goroutine to stop...")
	cancel()
	if err := eg.Wait(); err != nil {
		logrus.Error("Error waiting for goroutines: ", err)
	}
}

func main() {
	mountMap()
}
