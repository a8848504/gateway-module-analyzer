package capture

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gateway-module-analyzer/internal/analyze"
	"golang.org/x/sys/windows"
)

func TestCaptureSelectionAndOwnership(t *testing.T) {
	if converter := pktmonConverter("start, stop, format"); converter != "" {
		t.Fatalf("legacy Pktmon should use fallback, got %q", converter)
	}
	if pktmonConverter("etl2txt, etl2pcap") != "etl2pcap" || pktmonConverter("format, pcapng") != "pcapng" {
		t.Fatal("unsupported Pktmon converter selection")
	}
	if modernPktmonOptions("--etw -p <bytes>") || !modernPktmonOptions("--capture --pkt-size --log-mode --type") {
		t.Fatal("incorrect Pktmon capture syntax compatibility")
	}
	recording := `C:\Temp\our trace\capture.etl`
	if !netshOwnsCapture("Netsh 正在运行\r\n文件: \""+recording+"\"\r\n", recording) {
		t.Fatal("running Netsh trace belongs to current sample")
	}
	if netshOwnsCapture(`Trace File: C:\external\capture.etl`, recording) {
		t.Fatal("another application's trace was treated as owned")
	}
}

func TestNetshConverterBundle(t *testing.T) {
	converter, err := unpackNetshConverter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(converter)
	if err != nil {
		t.Fatal(err)
	}
	const expected = "c2d03aac43ea0f5626fc8d909e6688393feaf71bd6facd39aaf8a637382d9043"
	if got := fmt.Sprintf("%x", sha256.Sum256(binary)); got != expected {
		t.Fatalf("converter hash = %s", got)
	}
}

// The hosted Windows test runner is isolated from production capture sessions.
func TestNetshCompatibilityOnWindows(t *testing.T) {
	if os.Getenv("GATEWAY_TEST_NETSH") != "1" {
		t.Skip("requires an isolated Windows machine with administrator access")
	}
	directory, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	netsh := filepath.Join(directory, "netsh.exe")
	recording := filepath.Join(work, "capture.etl")
	if err := startNetsh(netsh, recording); err != nil {
		t.Fatal(err)
	}
	owned := true
	defer func() {
		if owned {
			if err := stopNetsh(netsh, recording); err != nil {
				t.Error(err)
			}
		}
	}()
	connection, err := net.DialTimeout("tcp", "api.github.com:443", 8*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	connection.Close()
	if err := stopNetsh(netsh, recording); err != nil {
		t.Fatal(err)
	}
	owned = false
	converter, err := unpackNetshConverter(work)
	if err != nil {
		t.Fatal(err)
	}
	converted := filepath.Join(work, "capture.pcapng")
	if err := convertNetsh(converter, recording, converted); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(converted)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	report, err := analyze.ReadCapture(context.Background(), file, 443, nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.TCPPackets == 0 {
		t.Fatal("converted Netsh capture contains no TCP packets for the test connection")
	}
	t.Logf("Netsh captured and converted %d TCP packets", report.TCPPackets)
}
