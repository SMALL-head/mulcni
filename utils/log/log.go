package log

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mattn/go-isatty"
	"github.com/sirupsen/logrus"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
)

type Formatter struct {
	isTerminal bool
}

func (m *Formatter) Format(entry *logrus.Entry) ([]byte, error) {
	var b bytes.Buffer
	timestamp := entry.Time.Format("2006-01-02 15:04:05")

	levelText := entry.Level.String()
	if m.isTerminal {
		switch entry.Level {
		case logrus.DebugLevel:
			levelText = colorCyan + levelText + colorReset
		case logrus.InfoLevel:
			levelText = colorGreen + levelText + colorReset
		case logrus.WarnLevel:
			levelText = colorYellow + levelText + colorReset
		case logrus.ErrorLevel, logrus.FatalLevel, logrus.PanicLevel:
			levelText = colorRed + levelText + colorReset
		}
	}

	if entry.HasCaller() {
		fileName := filepath.Base(entry.Caller.File)
		line := entry.Caller.Line
		fmt.Fprintf(&b, "%s [%s] %s:%d %s\n",
			timestamp, levelText, fileName, line, entry.Message)
	} else {
		fmt.Fprintf(&b, "%s [%s] %s\n",
			timestamp, levelText, entry.Message)
	}

	return b.Bytes(), nil
}

func init() {
	isTerminal := isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())
	f := Formatter{isTerminal: isTerminal}
	logrus.SetReportCaller(true)
	logrus.SetFormatter(&f)
}
