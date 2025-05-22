package tc

import (
	"os"
	"reflect"

	"github.com/SMALL-head/mulcni/utils/tctools"
	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
)

var (
	tcObjFilePath string
)

func init() {
	tcObjFilePath = os.Getenv("TC_REDIRECT_OBJ_FILE")
}

type UnMountTCFunc func() error

// MountMap mounts a map with the given name and pin path.
//
// pin at /sys/fs/bpf/tc/globals/{mapName} if pinPath is ""
func MountMap(mapName string, pinPath string, maxEntries uint32, key, value any) *ebpf.Map {
	if pinPath == "" {
		pinPath = "/sys/fs/bpf/tc/globals/"
	}
	keySize, valueSize := uint32(reflect.TypeOf(key).Size()), uint32(reflect.TypeOf(value).Size())
	// if reflect.TypeOf(key).Kind() == reflect.Ptr {
	// 	keySize = 16
	// }
	// if reflect.TypeOf(value).Kind() == reflect.Ptr {
	// 	valueSize = 16
	// }

	m, err := ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Name:       mapName,
		Pinning:    ebpf.PinByName, // 自动pin了
		Type:       ebpf.Hash,
		KeySize:    keySize,
		ValueSize:  valueSize,
		MaxEntries: maxEntries,
	}, ebpf.MapOptions{
		PinPath: pinPath,
	})
	if err != nil {
		logrus.Fatalf("Failed to create map: %v", err)
	}

	return m
}

// AttachTCRedirectProg 将环境变量中的“TC_REDIRECT_OBJ_FILE”中的tc obj文件挂载到指定的网卡上，并返回一个卸载函数

// 若环境变量为空，则默认使用"/root/mulcni/pkg/ebpfProc/tc/tc.o"文件
func AttachTCRedirectProg(ifaceName string) (UnMountTCFunc, error) {
	if tcObjFilePath == "" {
		tcObjFilePath = "/root/mulcni/pkg/ebpfProc/tc/tc.o"
	}
	unMountFunc := func() error {
		if err := tctools.DeleteIngressBPFFromIface(ifaceName); err != nil {
			// logrus.Errorf("Failed to delete ingress BPF from iface %s: %v", ifaceName, err)
			return err
		}
		return nil
	}
	return unMountFunc, tctools.AttachIngressBPFToIface(ifaceName, tcObjFilePath)
}
