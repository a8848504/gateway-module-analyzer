package capture

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gateway-module-analyzer/internal/analyze"
	"golang.org/x/sys/windows"
)

const diskReserve = 512 << 20

type traceFile struct {
	path  string
	size  int64
	index uint64
}

func traceFiles(work string) ([]traceFile, error) {
	items, err := os.ReadDir(work)
	if err != nil {
		return nil, err
	}
	var traces []traceFile
	for _, entry := range items {
		name := strings.ToLower(entry.Name())
		if entry.IsDir() || filepath.Ext(name) != ".etl" || !strings.HasPrefix(name, "capture") {
			continue
		}
		suffix := strings.TrimLeft(strings.TrimSuffix(strings.TrimPrefix(name, "capture"), ".etl"), "_-")
		var index uint64
		if suffix != "" {
			value, err := strconv.ParseUint(suffix, 10, 64)
			if err != nil {
				continue
			}
			index = value
		}
		info, err := entry.Info()
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		if info.Mode().IsRegular() && info.Size() > 0 {
			traces = append(traces, traceFile{path: filepath.Join(work, entry.Name()), size: info.Size(), index: index})
		}
	}
	sort.Slice(traces, func(i, j int) bool {
		if traces[i].index == traces[j].index {
			return traces[i].path < traces[j].path
		}
		return traces[i].index < traces[j].index
	})
	return traces, nil
}

func checkTraceSpace(work string, singleFile bool) error {
	path, err := windows.UTF16PtrFromString(work)
	if err != nil {
		return err
	}
	var free uint64
	if err := windows.GetDiskFreeSpaceEx(path, &free, nil, nil); err != nil {
		return fmt.Errorf("无法读取采样磁盘剩余空间: %w", err)
	}
	required := uint64(diskReserve)
	if singleFile {
		// Netsh produces a single file. Leave room for the converted copy.
		info, err := os.Stat(filepath.Join(work, "capture.etl"))
		if err == nil {
			required += uint64(info.Size()) + uint64(info.Size())/4
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("无法检查 Netsh 采样文件大小: %w", err)
		}
	}
	if free < required {
		return fmt.Errorf("采样盘空间不足（剩余 %d MiB，需保留 %d MiB）", free>>20, required>>20)
	}
	return nil
}

func traceWorkTimeout(size int64) time.Duration {
	return 90*time.Second + time.Duration(size/(8<<20))*time.Second
}

func analyzeTraces(work string, port uint16, local map[netip.Addr]bool, elapsed time.Duration, status func(string),
	convert func(recording, converted string, size int64) error) (*Sample, error) {
	traces, err := traceFiles(work)
	if err != nil {
		return nil, err
	}
	if len(traces) == 0 {
		return nil, errors.New("系统未生成含数据的采样文件")
	}
	session := analyze.NewSession(port, local)
	converted := filepath.Join(work, "capture.pcapng")
	for i, trace := range traces {
		status(fmt.Sprintf("正在转换采样文件 %d/%d（%.1f MiB）", i+1, len(traces), float64(trace.size)/(1<<20)))
		if err := convert(trace.path, converted, trace.size); err != nil {
			return nil, fmt.Errorf("转换 %s 失败: %w", filepath.Base(trace.path), err)
		}
		status(fmt.Sprintf("正在重组 TCP 并统计采样文件 %d/%d…", i+1, len(traces)))
		file, err := os.Open(converted)
		if err != nil {
			return nil, fmt.Errorf("无法打开 PCAPNG 转换结果: %w", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), traceWorkTimeout(trace.size))
		readErr := session.ReadCapture(ctx, file)
		cancel()
		file.Close()
		if readErr != nil {
			return nil, readErr
		}
		if err := os.Remove(converted); err != nil {
			return nil, fmt.Errorf("清理转换文件失败: %w", err)
		}
	}
	return &Sample{Report: session.Finish(0), Duration: elapsed}, nil
}
