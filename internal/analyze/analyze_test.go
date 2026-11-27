package analyze

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func seal(frame []byte, from int) []byte {
	for _, b := range frame[from : len(frame)-2] {
		frame[len(frame)-2] += b
	}
	return frame
}

func rFrame(id uint32) []byte {
	frame := []byte{'R', 0, 0, 0, 0, 0, 0, 0, 'A'}
	binary.BigEndian.PutUint32(frame[2:6], id)
	return seal(frame, 1)
}

func lFrame(id uint32) []byte {
	frame := []byte{'L', 2, 1, 0, 0, 0, 0, 90, 0, 0, 0, 0, 0, 0, 0, 0, 0, 'A'}
	binary.BigEndian.PutUint32(frame[8:12], id)
	return seal(frame, 1)
}

func wrap(payload []byte, gateway byte) []byte {
	frame := make([]byte, len(payload)+22)
	copy(frame, "ETHE")
	binary.BigEndian.PutUint16(frame[4:6], uint16(len(payload)))
	frame[6], frame[7] = 1, 1
	copy(frame[8:], payload)
	copy(frame[len(frame)-14:], []byte{192, 0, 2, 1, 0x13, 0x88, 2, 44, 33, 22, 11, gateway, 0, 'M'})
	return seal(frame, 4)
}

func TestCardReports(t *testing.T) {
	hj := make([]byte, 8+2*5)
	copy(hj, []byte{'H', 'J', 0, 1, 2, 0})
	hj[len(hj)-1] = 'E'
	binary.BigEndian.PutUint32(hj[6:], 0xaabbcc08)
	binary.BigEndian.PutUint32(hj[11:], 0xaabbcc0f)
	seal(hj, 2)
	broken := lFrame(0xaa33b800)
	broken[len(broken)-2]++
	raw := bytes.Join([][]byte{
		wrap(bytes.Join([][]byte{rFrame(0xaabbcc00), lFrame(0xaabbcc07), lFrame(0xaabbcc07), hj, broken}, nil), 1),
		wrap(rFrame(0xbbccdd08), 2),
		wrap(nil, 3),
	}, nil)
	report, err := ReadStream(bytes.NewReader(raw))
	if err != nil || len(report.Gateways) != 3 || report.OuterFrames != 3 {
		t.Fatalf("unexpected report: %+v %v", report, err)
	}
	first := report.Gateways[0]
	if first.Modules != [2]uint64{3, 2} || first.UniqueCards != 4 || first.BadInnerFrames != 1 ||
		first.Channels[0] != 1 || first.Channels[7] != 2 || first.Channels[8] != 1 || first.Channels[15] != 1 {
		t.Fatalf("incorrect channel distribution: %+v", first)
	}
	if report.Gateways[1].Modules != [2]uint64{0, 1} || report.Gateways[2].Modules != [2]uint64{} {
		t.Fatal("gateway counts were mixed")
	}
}

func tcpPacket(t *testing.T, seq uint32, syn bool, dest uint16, src, dst string, data []byte) []byte {
	t.Helper()
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.ParseIP(src), DstIP: net.ParseIP(dst), Protocol: layers.IPProtocolTCP}
	tcp := &layers.TCP{SrcPort: 40000, DstPort: layers.TCPPort(dest), Seq: seq, SYN: syn, ACK: !syn}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	eth := &layers.Ethernet{SrcMAC: []byte{2, 3, 4, 5, 6, 7}, DstMAC: []byte{2, 7, 6, 5, 4, 3}, EthernetType: layers.EthernetTypeIPv4}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ip, tcp, gopacket.Payload(data)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestLiveAndPCAPNGReassembly(t *testing.T) {
	const port = 7115
	const server = "192.0.2.1"
	const client = "192.0.2.2"
	first := wrap(rFrame(0x11223307), 1)
	second := wrap(rFrame(0x11223308), 1)
	var output bytes.Buffer
	writer, err := pcapgo.NewNgWriter(&output, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	local := map[netip.Addr]bool{netip.MustParseAddr(server): true}
	session := NewSession(port, local)
	row := func(seq uint32, syn bool, dest uint16, src, dst string, data []byte) {
		wire := tcpPacket(t, seq, syn, dest, src, dst, data)
		info := gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(wire), Length: len(wire)}
		if err := writer.WritePacket(info, wire); err != nil {
			t.Fatal(err)
		}
		if err := session.AddPacket(wire, info, layers.LinkTypeEthernet); err != nil {
			t.Fatal(err)
		}
	}
	row(100, true, port, client, server, nil)
	row(116, false, port, client, server, first[15:])
	row(116, false, port, client, server, first[15:])
	if current := session.Snapshot(); len(current.Gateways) != 0 {
		t.Fatal("out-of-order bytes counted before reassembly")
	}
	row(101, false, port, client, server, first[:15])
	row(101, false, port, client, server, first)
	row(101, false, port+1, client, server, first)
	row(101, false, port, server, client, first)
	if current := session.Snapshot(); len(current.Gateways) != 1 || current.Gateways[0].Modules != [2]uint64{1, 0} {
		t.Fatalf("live snapshot is inaccurate: %+v", current)
	}
	row(101+uint32(len(first)), false, port, client, server, second)
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	offline, err := ReadCapture(context.Background(), &output, port, local)
	if err != nil {
		t.Fatal(err)
	}
	for _, report := range []*Report{offline, session.Finish(0)} {
		if len(report.Gateways) != 1 || report.Gateways[0].Modules != [2]uint64{1, 1} || report.TCPGaps != 0 {
			t.Fatalf("recovery, retransmission or direction failed: %+v", report)
		}
	}
}

func TestLiveGapResumesAtNextFrame(t *testing.T) {
	report := newReport()
	stream := tcpStream{pending: map[uint32][]byte{}, decoder: decoder{report: report}}
	var pendingBytes int
	partial := wrap(rFrame(1), 1)[:7]
	if err := stream.add(100, partial, &pendingBytes); err != nil {
		t.Fatal(err)
	}
	if err := stream.add(120, wrap(rFrame(9), 1), &pendingBytes); err != nil {
		t.Fatal(err)
	}
	stream.drain(&pendingBytes, true)
	if report.TCPGaps != 1 || report.MissingTCPBytes != 13 || report.PartialOuterFrames != 1 ||
		report.Gateways[0].Modules != [2]uint64{0, 1} || pendingBytes != 0 {
		t.Fatalf("recovery crossed a TCP gap: %+v", report)
	}
}
