package capture

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
	"unsafe"

	"gateway-module-analyzer/internal/analyze"
	"golang.org/x/sys/windows"
)

const pktmonSegmentMiB = 128

var activeSession = regexp.MustCompile(`(?im)^\s*pktmon(?:\s|$)`)
var noFilters = regexp.MustCompile(`(?im)^\s*(?:none[。.]?|no (?:packet )?filters?(?:\s.*)?|无[。.]?|没有(?:任何)?(?:数据包)?(?:筛选器|过滤器)[。.]?|未设置(?:任何)?(?:数据包)?(?:筛选器|过滤器)[。.]?)\s*$`)

func outputText(data []byte) string {
	if len(data) >= 2 && len(data)%2 == 0 &&
		(data[1] == 0 || (data[0] == 0xff && data[1] == 0xfe)) {
		if data[0] == 0xff && data[1] == 0xfe {
			data = data[2:]
		}
		words := make([]uint16, len(data)/2)
		for i := range words {
			words[i] = binary.LittleEndian.Uint16(data[i*2:])
		}
		return windows.UTF16ToString(words)
	}
	if utf8.Valid(data) {
		return string(data)
	}
	output := make([]uint16, len(data))
	if len(data) != 0 {
		proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("MultiByteToWideChar")
		n, _, _ := proc.Call(0, 0, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)),
			uintptr(unsafe.Pointer(&output[0])), uintptr(len(output)))
		if n != 0 {
			return windows.UTF16ToString(output[:n])
		}
	}
	return strings.ToValidUTF8(string(data), "�")
}

func command(timeout time.Duration, tool string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, tool, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	data, err := cmd.CombinedOutput()
	output := strings.TrimSpace(outputText(data))
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return output, fmt.Errorf("%s %s: %w %s", filepath.Base(tool), args[0], err, output)
	}
	return output, nil
}

type Sample struct {
	Report   *analyze.Report
	Duration time.Duration
	Warning  string
}

func localAddresses() (map[netip.Addr]bool, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("读取本机 IP 失败: %w", err)
	}
	local := make(map[netip.Addr]bool)
	for _, addr := range addrs {
		if prefix, parseErr := netip.ParsePrefix(addr.String()); parseErr == nil {
			local[prefix.Addr().Unmap()] = true
		}
	}
	if len(local) == 0 {
		return nil, errors.New("没有找到本机网卡地址")
	}
	return local, nil
}

// Run owns its own capture session and cleans up its named filter.
// A closed stop channel ends sampling early and still returns the report.
func Run(port uint16, duration time.Duration, stop <-chan struct{}, status func(string)) (_ *Sample, resultErr error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	name, _ := windows.UTF16PtrFromString(`Local\GatewayModuleAnalyzerCapture`)
	mutex, err := windows.CreateMutex(nil, false, name)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(mutex)
	wait, err := windows.WaitForSingleObject(mutex, 0)
	if err != nil || (wait != windows.WAIT_OBJECT_0 && wait != windows.WAIT_ABANDONED) {
		return nil, errors.New("已有网关分析采样任务在运行")
	}
	defer windows.ReleaseMutex(mutex)

	directory, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	pktmon := filepath.Join(directory, "pktmon.exe")
	help, _ := command(10*time.Second, pktmon, "help")
	converter := pktmonConverter(help)
	if converter != "" {
		startHelp, _ := command(10*time.Second, pktmon, "start", "help")
		if !modernPktmonOptions(startHelp) {
			converter = ""
		}
	}
	sessions, err := command(15*time.Second, filepath.Join(directory, "logman.exe"), "query", "-ets")
	if err != nil {
		return nil, fmt.Errorf("检查系统抓包会话失败: %w", err)
	}
	if activeSession.MatchString(sessions) {
		return nil, errors.New("系统已有 Pktmon 抓包会话，请等当前会话结束后再采样")
	}
	if converter == "" {
		return runNetsh(directory, sessions, port, duration, stop, status)
	}
	filters, err := command(15*time.Second, pktmon, "filter", "list")
	if err != nil {
		return nil, err
	}
	if !noFilters.MatchString(filters) {
		return nil, fmt.Errorf("系统已有 Pktmon 筛选规则或无法识别其状态，请交由管理员检查。当前状态：%s", filters)
	}
	local, err := localAddresses()
	if err != nil {
		return nil, err
	}

	work, err := os.MkdirTemp("", "gateway-module-capture-")
	if err != nil {
		return nil, err
	}
	keepCapture := false
	defer func() {
		if !keepCapture {
			os.RemoveAll(work)
		}
	}()
	recording := filepath.Join(work, "capture.etl")
	checkStorage := func() error { return checkTraceSpace(work, false) }
	if err := checkStorage(); err != nil {
		return nil, err
	}
	filter := "Gateway_" + hex.EncodeToString(randBytes())
	if _, err := command(15*time.Second, pktmon, "filter", "add", filter, "-t", "TCP", "-p", strconv.Itoa(int(port))); err != nil {
		return nil, err
	}
	defer func() {
		if _, err := command(15*time.Second, pktmon, "filter", "remove", filter); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("清理抓包筛选规则 %s 失败: %w", filter, err))
		}
	}()
	status("正在启动旁路采样…")
	if _, err := command(20*time.Second, pktmon, "start", "--capture", "--comp", "nics",
		"--type", "flow", "--pkt-size", "0", "--file-name", recording, "--file-size",
		strconv.Itoa(pktmonSegmentMiB), "--log-mode", "multi-file"); err != nil {
		return nil, fmt.Errorf("启动 Pktmon 失败: %w", err)
	}
	elapsed, warning := waitSampling(port, duration, stop, status, checkStorage)
	status("正在停止采样并整理报文…")
	if _, err := command(40*time.Second, pktmon, "stop"); err != nil {
		keepCapture = true
		return nil, fmt.Errorf("停止 Pktmon 失败，采样文件位于 %s：%w", work, err)
	}
	sample, err := analyzeTraces(work, port, local, elapsed, status, func(recording, converted string, size int64) error {
		timeout := traceWorkTimeout(size)
		if _, err := command(timeout, pktmon, converter, recording, "--out", converted); err != nil {
			alternate := "pcapng"
			if converter == alternate {
				alternate = "etl2pcap"
			}
			if _, alternateErr := command(timeout, pktmon, alternate, recording, "--out", converted); alternateErr != nil {
				return errors.Join(err, alternateErr)
			}
		}
		return nil
	})
	if err != nil {
		keepCapture = true
		return nil, fmt.Errorf("分析失败，原始数据位于 %s：%w", work, err)
	}
	sample.Warning = warning
	return sample, nil
}

func pktmonConverter(help string) string {
	help = strings.ToLower(help)
	if strings.Contains(help, "etl2pcap") {
		return "etl2pcap"
	}
	if strings.Contains(help, "pcapng") {
		return "pcapng"
	}
	return ""
}

func modernPktmonOptions(help string) bool {
	help = strings.ToLower(help)
	return strings.Contains(help, "--capture") && strings.Contains(help, "--pkt-size") &&
		strings.Contains(help, "--log-mode") && strings.Contains(help, "--type")
}

func waitSampling(port uint16, duration time.Duration, stop <-chan struct{}, status func(string), checkStorage func() error) (time.Duration, string) {
	start := time.Now()
	timer := time.NewTimer(duration)
	defer timer.Stop()
	ticks := time.NewTicker(time.Second)
	defer ticks.Stop()
	for {
		status(fmt.Sprintf("正在采样 TCP %d · 剩余 %d 秒", port, max(0, int((duration-time.Since(start)).Seconds()+0.99))))
		select {
		case <-stop:
			return time.Since(start), ""
		case <-timer.C:
			return time.Since(start), ""
		case <-ticks.C:
			if err := checkStorage(); err != nil {
				return time.Since(start), "采样提前结束，" + err.Error()
			}
		}
	}
}

func randBytes() []byte {
	var data [5]byte
	rand.Read(data[:])
	return data[:]
}
