package capture

import (
	"embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

//go:embed third_party/etl2pcapng/etl2pcapng.exe third_party/etl2pcapng/LICENSE.txt
var netshConverterFiles embed.FS

var netshSession = regexp.MustCompile(`(?im)^\s*NetTrace(?:[-\s]|$)`)

func netshOwnsCapture(output, recording string) bool {
	for _, line := range strings.Split(output, "\n") {
		line = strings.Trim(strings.TrimSpace(line), `"`)
		if strings.HasSuffix(strings.ToLower(line), strings.ToLower(recording)) {
			return true
		}
	}
	return false
}

func startNetsh(netsh, recording string) error {
	// Netsh filters by protocol. The analyzer filters the destination port and
	// local addresses when reading the file.
	_, startErr := command(25*time.Second, netsh, "trace", "start", "capture=yes", "report=disabled",
		"persistent=no", "correlation=no", "perfmerge=no", "filemode=circular",
		"maxsize="+strconv.Itoa(fileLimitMiB), "protocol=TCP", "tracefile="+recording)
	current, statusErr := command(10*time.Second, netsh, "trace", "show", "status")
	if statusErr == nil && netshOwnsCapture(current, recording) {
		return nil
	}
	if startErr != nil {
		return fmt.Errorf("无法启动 Netsh 兼容抓包: %w", startErr)
	}
	if statusErr != nil {
		return fmt.Errorf("无法检查 Netsh 抓包状态: %w", statusErr)
	}
	return errors.New("无法确认 Netsh 已启动本次采样，请检查系统抓包状态")
}

func stopNetsh(netsh, recording string) error {
	current, err := command(10*time.Second, netsh, "trace", "show", "status")
	if err != nil {
		return fmt.Errorf("无法检查当前 Netsh 会话: %w", err)
	}
	if !netshOwnsCapture(current, recording) {
		return errors.New("当前 Netsh 会话的输出文件与本次采样不符")
	}
	if _, err := command(60*time.Second, netsh, "trace", "stop"); err != nil {
		return fmt.Errorf("停止 Netsh 兼容抓包失败: %w", err)
	}
	return nil
}

func unpackNetshConverter(work string) (string, error) {
	for _, name := range []string{"etl2pcapng.exe", "LICENSE.txt"} {
		data, err := netshConverterFiles.ReadFile("third_party/etl2pcapng/" + name)
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(work, name), data, 0600); err != nil {
			return "", err
		}
	}
	return filepath.Join(work, "etl2pcapng.exe"), nil
}

func convertNetsh(converter, recording, converted string) error {
	output, err := command(90*time.Second, converter, recording, converted)
	if err != nil {
		return fmt.Errorf("转换 Netsh 采样文件失败: %w", err)
	}
	info, err := os.Stat(converted)
	if err == nil && info.Size() >= 28 {
		return nil
	}
	if strings.Contains(strings.ToLower(output), "does not contain an ndiscap packet capture") {
		return errors.New("Netsh 未抓到可转换的网络包。请确认在定位服务所在的服务器上运行，网关正在上报，或改用 Npcap 实时采样")
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("无法检查 Netsh 转换结果: %w", err)
	}
	return fmt.Errorf("Netsh 转换未生成可用的 PCAPNG 文件。%s", strings.TrimSpace(output))
}

func runNetsh(directory, sessions string, port uint16, duration time.Duration, stop <-chan struct{}, status func(string)) (_ *Sample, resultErr error) {
	if netshSession.MatchString(sessions) {
		return nil, errors.New("系统已有 Netsh 网络抓包会话，请在该会话结束后再采样")
	}
	local, err := localAddresses()
	if err != nil {
		return nil, err
	}
	work, err := os.MkdirTemp("", "gateway-netsh-capture-")
	if err != nil {
		return nil, err
	}
	recording := filepath.Join(work, "capture.etl")
	defer func() {
		if resultErr != nil {
			if info, err := os.Stat(recording); err == nil && info.Size() > 0 {
				resultErr = fmt.Errorf("%w\n原始采样位于 %s", resultErr, work)
				return
			}
		}
		os.RemoveAll(work)
	}()
	converter, err := unpackNetshConverter(work)
	if err != nil {
		return nil, fmt.Errorf("无法准备 Netsh 转换组件: %w", err)
	}
	netsh := filepath.Join(directory, "netsh.exe")
	status("此系统使用 Netsh 兼容采样…")
	if err := startNetsh(netsh, recording); err != nil {
		return nil, err
	}
	elapsed := waitSampling(port, duration, stop, status)
	status("正在停止 Netsh 采样…")
	if err := stopNetsh(netsh, recording); err != nil {
		return nil, err
	}
	status("正在转换 Netsh 采样文件…")
	converted := filepath.Join(work, "capture.pcapng")
	if err := convertNetsh(converter, recording, converted); err != nil {
		return nil, err
	}
	return analyzeCapture(recording, converted, port, local, elapsed, status)
}
