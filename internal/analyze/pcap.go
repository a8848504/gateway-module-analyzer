package analyze

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

type connection struct {
	source, target netip.AddrPort
}

type tcpStream struct {
	started, hasSYN bool
	next, syn       uint32
	pending         map[uint32][]byte
	decoder         decoder
	gapSince        time.Time
}

func (s *tcpStream) consume(sequence uint32, data []byte) {
	overlap := -int64(int32(sequence - s.next))
	if overlap >= int64(len(data)) {
		return
	}
	data = data[overlap:]
	s.next += uint32(len(data))
	s.decoder.feed(data)
}

func (s *tcpStream) drain(pendingBytes *int, finish bool) {
	for len(s.pending) > 0 {
		var sequence uint32
		var distance int32
		first := true
		for candidate := range s.pending {
			diff := int32(candidate - s.next)
			if first || diff < distance {
				sequence, distance, first = candidate, diff, false
			}
		}
		if distance > 0 {
			if !finish {
				return
			}
			s.decoder.report.TCPGaps++
			s.decoder.report.MissingTCPBytes += uint64(distance)
			s.decoder.interrupt()
			s.next = sequence
		}
		data := s.pending[sequence]
		delete(s.pending, sequence)
		*pendingBytes -= len(data)
		s.consume(sequence, data)
	}
	s.gapSince = time.Time{}
}

func (s *tcpStream) add(sequence uint32, data []byte, pendingBytes *int) error {
	if !s.started {
		s.next, s.started = sequence, true
	}
	if int32(sequence-s.next) <= 0 {
		s.consume(sequence, data)
		s.drain(pendingBytes, false)
		return nil
	}
	oldSize := len(s.pending[sequence])
	if oldSize >= len(data) {
		return nil
	}
	if *pendingBytes+len(data)-oldSize > 32<<20 || len(s.pending) >= 4096 {
		return errors.New("TCP 缺口后的乱序数据过多，请缩短采样时间")
	}
	s.pending[sequence] = bytes.Clone(data)
	*pendingBytes += len(data) - oldSize
	if s.gapSince.IsZero() {
		s.gapSince = time.Now()
	}
	return nil
}

type Session struct {
	port         uint16
	local        map[netip.Addr]bool
	report       *Report
	streams      map[connection]*tcpStream
	pendingBytes int
}

func NewSession(port uint16, local map[netip.Addr]bool) *Session {
	return &Session{port: port, local: local, report: newReport(), streams: make(map[connection]*tcpStream)}
}

// ResumeAfterGaps keeps live totals moving when the capture missed bytes.
func (s *Session) ResumeAfterGaps(age time.Duration) {
	for _, stream := range s.streams {
		if !stream.gapSince.IsZero() && time.Since(stream.gapSince) >= age {
			stream.drain(&s.pendingBytes, true)
		}
	}
}

func (s *Session) Snapshot() *Report { return s.report.snapshot() }

func (s *Session) Finish(dropped uint64) *Report {
	for _, stream := range s.streams {
		stream.drain(&s.pendingBytes, true)
		stream.decoder.interrupt()
	}
	s.report.CaptureDropped = dropped
	return s.Snapshot()
}

type packetReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
}

// ReadCapture reconstructs the TCP direction towards the positioning server.
// If local is empty, the destination port alone selects this direction.
func ReadCapture(ctx context.Context, input io.Reader, port uint16, local map[netip.Addr]bool) (*Report, error) {
	buffer := bufio.NewReader(input)
	magic, err := buffer.Peek(4)
	if err != nil {
		return nil, fmt.Errorf("抓包文件为空或不完整: %w", err)
	}
	var reader packetReader
	if bytes.Equal(magic, []byte{0x0a, 0x0d, 0x0d, 0x0a}) {
		options := pcapgo.DefaultNgReaderOptions
		options.WantMixedLinkType = true
		reader, err = pcapgo.NewNgReader(buffer, options)
	} else {
		reader, err = pcapgo.NewReader(buffer)
	}
	if err != nil {
		return nil, err
	}

	session := NewSession(port, local)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, captureInfo, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("读取抓包文件失败: %w", err)
		}
		link := reader.LinkType()
		if len(captureInfo.AncillaryData) != 0 {
			if value, ok := captureInfo.AncillaryData[0].(layers.LinkType); ok {
				link = value
			}
		}
		if err := session.AddPacket(data, captureInfo, link); err != nil {
			return nil, err
		}
	}
	return session.Finish(0), nil
}

func (s *Session) AddPacket(data []byte, captureInfo gopacket.CaptureInfo, link layers.LinkType) error {
	packet := gopacket.NewPacket(data, link, gopacket.NoCopy)
	network := packet.NetworkLayer()
	if network == nil {
		if packet.ErrorLayer() != nil {
			s.report.UnsupportedPackets++
		}
		return nil
	}
	if ip, ok := network.(*layers.IPv4); ok &&
		(ip.FragOffset != 0 || ip.Flags&layers.IPv4MoreFragments != 0) {
		s.report.UnsupportedPackets++
		return nil
	}
	if packet.Layer(layers.LayerTypeIPv6Fragment) != nil {
		s.report.UnsupportedPackets++
		return nil
	}
	tcp, ok := packet.TransportLayer().(*layers.TCP)
	if !ok || uint16(tcp.DstPort) != s.port {
		return nil
	}
	flow := network.NetworkFlow()
	src, srcOK := netip.AddrFromSlice(flow.Src().Raw())
	dst, dstOK := netip.AddrFromSlice(flow.Dst().Raw())
	if !srcOK || !dstOK || (len(s.local) != 0 && !s.local[dst.Unmap()]) {
		return nil
	}
	s.report.TCPPackets++
	if captureInfo.CaptureLength < captureInfo.Length || packet.Metadata().Truncated {
		s.report.CaptureTruncated++
	}
	if len(tcp.Payload) == 0 && !tcp.SYN {
		return nil
	}
	key := connection{netip.AddrPortFrom(src, uint16(tcp.SrcPort)), netip.AddrPortFrom(dst, s.port)}
	stream := s.streams[key]
	if stream != nil && tcp.SYN && (!stream.hasSYN || stream.syn != tcp.Seq) {
		stream.drain(&s.pendingBytes, true)
		stream.decoder.interrupt()
		stream = nil
	}
	if stream == nil {
		if _, existed := s.streams[key]; !existed && len(s.streams) >= 4096 {
			return errors.New("TCP 连接数过多，请缩短采样时间")
		}
		stream = &tcpStream{
			pending: make(map[uint32][]byte),
			decoder: decoder{report: s.report},
		}
		s.streams[key] = stream
	}
	seq := tcp.Seq
	if tcp.SYN {
		seq++
		if !stream.started {
			stream.started, stream.hasSYN, stream.next, stream.syn = true, true, seq, tcp.Seq
		}
	}
	if len(tcp.Payload) != 0 {
		return stream.add(seq, tcp.Payload, &s.pendingBytes)
	}
	return nil
}
