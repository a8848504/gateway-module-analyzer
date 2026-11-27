package capture

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"gateway-module-analyzer/internal/analyze"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

type packet struct {
	data []byte
	info gopacket.CaptureInfo
	link layers.LinkType
}

type deviceResult struct {
	dropped int
	err     error
}

func liveDevices(port uint16, local map[netip.Addr]bool) ([]*pcap.Handle, []string, error) {
	if err := pcap.LoadWinPCAP(); err != nil {
		return nil, nil, errors.New("实时模式需要 Windows 已安装 Npcap。可切换为 Pktmon 采样")
	}
	if !strings.Contains(strings.ToLower(pcap.Version()), "npcap") {
		return nil, nil, errors.New("实时模式需要 Npcap，请升级旧版 WinPcap，或切换为 Pktmon 采样")
	}
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, nil, fmt.Errorf("无法枚举 Npcap 网卡: %w", err)
	}
	var handles []*pcap.Handle
	var warnings []string
	filter := fmt.Sprintf("tcp dst port %d", port)
	for _, device := range devices {
		selected := strings.EqualFold(device.Name, `\Device\NPF_Loopback`)
		for _, address := range device.Addresses {
			if ip, ok := netip.AddrFromSlice(address.IP); ok && local[ip.Unmap()] {
				selected = true
				break
			}
		}
		if !selected {
			continue
		}
		name := device.Description
		if name == "" {
			name = device.Name
		}
		handle, err := pcap.OpenLive(device.Name, 65535+256, false, 200*time.Millisecond)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s 抓包启动失败：%v", name, err))
			continue
		}
		deviceFilter := filter
		if handle.LinkType() == layers.LinkTypeEthernet {
			deviceFilter += " or (vlan and " + filter + " or (vlan and " + filter + "))"
		}
		if err := handle.SetBPFFilter(deviceFilter); err != nil {
			handle.Close()
			warnings = append(warnings, fmt.Sprintf("%s 设置 TCP 筛选失败：%v", name, err))
			continue
		}
		handles = append(handles, handle)
	}
	if len(handles) == 0 {
		return nil, nil, fmt.Errorf("没有可用于实时采样的网卡。请检查 Npcap 权限和网卡状态。%s", strings.Join(warnings, "；"))
	}
	return handles, warnings, nil
}

func readDevice(ctx context.Context, handle *pcap.Handle, packets chan<- packet) (result deviceResult) {
	defer handle.Close()
	defer func() {
		stats, err := handle.Stats()
		if err != nil {
			result.err = errors.Join(result.err, fmt.Errorf("读取 Npcap 丢包计数失败: %w", err))
			return
		}
		result.dropped = stats.PacketsDropped + stats.PacketsIfDropped
	}()
	link := handle.LinkType()
	for ctx.Err() == nil {
		data, info, err := handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		}
		if err != nil {
			result.err = fmt.Errorf("一个网卡的实时抓包已中断: %w", err)
			break
		}
		select {
		case packets <- packet{data, info, link}:
		case <-ctx.Done():
			return result
		}
	}
	return result
}

// RunLive reads in passive, non-promiscuous mode and reports cumulative
// snapshots during collection. TCP and protocol processing use one goroutine.
func RunLive(port uint16, duration time.Duration, stop <-chan struct{}, status func(string), refresh func(*Sample)) (*Sample, error) {
	local, err := localAddresses()
	if err != nil {
		return nil, err
	}
	handles, warnings, err := liveDevices(port, local)
	if err != nil {
		return nil, err
	}
	session := analyze.NewSession(port, local)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	packets := make(chan packet, 256)
	results := make(chan deviceResult, len(handles))
	var devices sync.WaitGroup
	for _, handle := range handles {
		devices.Go(func() { results <- readDevice(ctx, handle, packets) })
	}
	go func() {
		devices.Wait()
		close(packets)
		close(results)
	}()

	start := time.Now()
	deadline := time.NewTimer(duration)
	defer deadline.Stop()
	ticks := time.NewTicker(time.Second)
	defer ticks.Stop()
	var analyzeErr error
	var elapsed time.Duration
	for packets != nil {
		select {
		case <-stop:
			stop = nil
			if elapsed == 0 {
				elapsed = time.Since(start)
			}
			cancel()
		case <-deadline.C:
			if elapsed == 0 {
				elapsed = time.Since(start)
			}
			cancel()
		case <-ticks.C:
			if elapsed == 0 {
				session.ResumeAfterGaps(2 * time.Second)
				status(fmt.Sprintf("实时采样 TCP %d · 剩余 %d 秒", port, max(0, int((duration-time.Since(start)).Seconds()+0.99))))
				refresh(&Sample{Report: session.Snapshot(), Duration: time.Since(start), Warning: strings.Join(warnings, "；")})
			}
		case incoming, ok := <-packets:
			if !ok {
				packets = nil
				continue
			}
			if analyzeErr == nil {
				analyzeErr = session.AddPacket(incoming.data, incoming.info, incoming.link)
				if analyzeErr != nil {
					cancel()
				}
			}
		}
	}
	if analyzeErr != nil {
		return nil, analyzeErr
	}
	if elapsed == 0 {
		elapsed = time.Since(start)
	}
	var dropped uint64
	for result := range results {
		dropped += uint64(max(0, result.dropped))
		if result.err != nil {
			warnings = append(warnings, result.err.Error())
		}
	}
	return &Sample{Report: session.Finish(dropped), Duration: elapsed, Warning: strings.Join(warnings, "；")}, nil
}
