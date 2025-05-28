package tc

import (
	"os"
	"reflect"

	"github.com/SMALL-head/mulcni/utils/tctools"
	"github.com/cilium/ebpf"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
)

var (
	tcObjFilePath      string
	tcVxlanEgressPath  string
	tcVxlanIngressPath string
)

type IPSrcKey struct {
	Sa uint32
}

type IPDstKey struct {
	Da uint32
}

type IPDstValue struct {
	Da         uint32
	IfaceIndex uint32
	Mac        [6]uint8
	Padding    [2]uint8 // 没有意义，9字节对齐用的
}

type DIPVxlanValue struct {
	IfaceIndex [8]uint32
	VxlanIP    [8]uint32
}

func init() {
	if err := godotenv.Load(); err != nil {
		logrus.Warnf("Failed to load .env file: %v", err)
	} else {
		logrus.Infof(".env file loaded successfully")
	}
	tcObjFilePath = os.Getenv("TC_REDIRECT_OBJ_FILE")
	tcVxlanEgressPath = os.Getenv("TC_VXLAN_EGRESS_OBJ_FILE")
	tcVxlanIngressPath = os.Getenv("TC_VXLAN_INGRESS_OBJ_FILE")
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

func AttachTCVxlanEgressProg(ifaceName string) (UnMountTCFunc, error) {
	if tcVxlanEgressPath == "" {
		tcVxlanEgressPath = "/root/mulcni/pkg/ebpfProc/vxlan/vxlan_egress.o"
	}
	if !tctools.ExistsQdisc(ifaceName) {
		if err := tctools.AddClsactQdiscIntoDev(ifaceName); err != nil {
			logrus.Errorf("Failed to add clsact qdisc into iface %s: %v", ifaceName, err)
			return nil, err
		}
	}
	unMountFunc := func() error {
		if err := tctools.DeleteEgressBPFFromIface(ifaceName); err != nil {
			logrus.Errorf("Failed to delete egress BPF from iface %s: %v", ifaceName, err)
			return err
		}
		return nil
	}
	return unMountFunc, tctools.AttachEgressBPFToIface(ifaceName, tcVxlanEgressPath)
}

func AttachTCVxlanIngressProg(ifaceName string) (UnMountTCFunc, error) {
	if tcVxlanIngressPath == "" {
		tcVxlanIngressPath = "/root/mulcni/pkg/ebpfProc/vxlan/vxlan_ingress.o"
	}
	if !tctools.ExistsQdisc(ifaceName) {
		if err := tctools.AddClsactQdiscIntoDev(ifaceName); err != nil {
			logrus.Errorf("Failed to add clsact qdisc into iface %s: %v", ifaceName, err)
			return nil, err
		}
	}
	unMountFunc := func() error {
		if err := tctools.DeleteIngressBPFFromIface(ifaceName); err != nil {
			logrus.Errorf("Failed to delete ingress BPF from iface %s: %v", ifaceName, err)
			return err
		}
		return nil
	}
	return unMountFunc, tctools.AttachIngressBPFToIface(ifaceName, tcVxlanIngressPath)
}
