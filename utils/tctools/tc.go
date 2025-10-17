package tctools

import (
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
)

func execCmd(cmd string) (string, error) {
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func ExistsQdisc(ifaceName string) bool {
	out, _ := execCmd("tc qdisc show dev " + ifaceName)
	// out, _ := processInfo.Output()
	logrus.Debugf("tc qdisc show dev %s output: %s", ifaceName, out)
	return strings.Contains(string(out), "clsact")
}

func AddClsactQdiscIntoDev(ifaceName string) error {
	if ExistsQdisc(ifaceName) {
		logrus.Infof("clsact qdisc already exists on iface %s", ifaceName)
		return nil
	}
	cmd := "tc qdisc add dev " + ifaceName + " clsact"
	_, err := execCmd(cmd)
	if err != nil {
		return err
	}
	return nil
}

func AttachIngressBPFToIface(ifaceName string, bpfFilePath string, secName string) error {
	cmd := "tc filter add dev " + ifaceName + " ingress bpf direct-action obj " + bpfFilePath + " sec " + secName
	res, err := execCmd(cmd)
	if err != nil {
		logrus.Errorf("mount bpf file %s to iface %s failed, output = %v, err = %v", bpfFilePath, ifaceName, res, err)
		return err
	}
	return nil
}

func AttachEgressBPFToIface(ifaceName string, bpfFilePath string, secName string) error {
	cmd := "tc filter add dev " + ifaceName + " egress bpf direct-action obj " + bpfFilePath + " sec " + secName
	res, err := execCmd(cmd)
	if err != nil {
		logrus.Errorf("mount bpf file %s to iface %s failed, output = %v, err = %v", bpfFilePath, ifaceName, res, err)
		return err
	}
	return nil
}

func DeleteIngressBPFFromIface(ifaceName string) error {
	cmd := "tc filter del dev " + ifaceName + " ingress"
	_, err := execCmd(cmd)
	if err != nil {
		return err
	}
	return nil
}

func DeleteEgressBPFFromIface(ifaceName string) error {
	cmd := "tc filter del dev " + ifaceName + " egress"
	_, err := execCmd(cmd)
	if err != nil {
		return err
	}
	return nil
}
