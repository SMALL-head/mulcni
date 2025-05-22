package tctools

import (
	"os/exec"

	"github.com/sirupsen/logrus"
)

func execCmd(cmd string) (string, error) {
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func AddClsactQdiscIntoDev(ifaceName string) error {
	cmd := "tc qdisc add dev " + ifaceName + " clsact"
	_, err := execCmd(cmd)
	if err != nil {
		return err
	}
	return nil
}

func AttachIngressBPFToIface(ifaceName string, bpfFilePath string) error {
	cmd := "tc filter add dev " + ifaceName + " ingress bpf direct-action obj " + bpfFilePath
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
