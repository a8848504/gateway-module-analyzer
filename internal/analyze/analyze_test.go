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

func TestEthernetAndCellularPackaging(t *testing.T) {
	makeFrame := func(kind, direction, gateway byte, prefix []byte, card uint32) []byte {
		frame := wrap(rFrame(card), gateway)
		frame[6], frame[7] = kind, direction
		copy(frame[len(frame)-14:], prefix)
		frame[len(frame)-2] = 0
		return seal(frame, 4)
	}
	sim := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab}
	data := bytes.Join([][]byte{
		makeFrame(ethernetGateway, 1, 1, nil, 0x12345600),
		makeFrame(plaintextEthernetGateway, 1, 1, nil, 0x12345608),
		makeFrame(plaintextCellularGateway, 1, 2, sim, 0x1234560f),
		makeFrame(plaintextCellularGateway, 1, 2, []byte{1, 2, 3, 4, 5, 6}, 0x12345607),
		makeFrame(plaintextEthernetGateway, etheDownlink, 3, nil, 0x12345600),
		makeFrame(encryptionHandshake, 1, 4, nil, 0x12345600),
		makeFrame(encryptedEthernetGateway, 1, 5, nil, 0x12345600),
		makeFrame(encryptedCellularGateway, 1, 6, nil, 0x12345600),
	}, nil)
	report, err := ReadStream(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if report.OuterFrames != 8 || report.BadOuterFrames != 0 || report.DownlinkOuterFrames != 1 ||
		report.HandshakeOuterFrames != 1 || report.EncryptedOuterFrames != 2 || len(report.Gateways) != 2 {
		t.Fatalf("incorrect outer frame classification: %+v", report)
	}
	for _, gateway := range report.Gateways {
		if gateway.Modules != [2]uint64{1, 1} || gateway.UnknownBytes != 0 {
			t.Fatalf("incorrect plaintext card data: %+v", gateway)
		}
		switch gateway.MAC {
		case "02:2C:21:16:0B:01":
			if gateway.Address != "192.0.2.1:5000" || gateway.SIMHex != "" {
				t.Fatalf("incorrect ethernet identity: %+v", gateway)
			}
		case "02:2C:21:16:0B:02":
			if gateway.Address != "" || gateway.SIMHex != "0123456789AB" {
				t.Fatalf("incorrect cellular identity: %+v", gateway)
			}
		default:
			t.Fatalf("unexpected gateway: %+v", gateway)
		}
	}
}

func TestOuterFrameFailureBreakdown(t *testing.T) {
	tail := wrap(rFrame(0x12345600), 1)
	tail[len(tail)-1] = 'X'
	checksum := wrap(rFrame(0x12345601), 1)
	checksum[len(checksum)-2]++
	valid := wrap(rFrame(0x12345608), 1)
	report, err := ReadStream(bytes.NewReader(bytes.Join([][]byte{tail, checksum, valid}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if report.BadOuterFrames != 2 || report.BadOuterTail != 1 || report.BadOuterChecksum != 1 ||
		report.OuterFrames != 1 || len(report.Gateways) != 1 || report.Gateways[0].Modules != [2]uint64{0, 1} {
		t.Fatalf("bad outer candidates were counted or misclassified: %+v", report)
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
	at := time.Now()
	if err := stream.add(100, partial, &pendingBytes, at); err != nil {
		t.Fatal(err)
	}
	if err := stream.add(120, wrap(rFrame(9), 1), &pendingBytes, at); err != nil {
		t.Fatal(err)
	}
	stream.drain(&pendingBytes, true)
	if report.TCPGaps != 1 || report.MissingTCPBytes != 13 || report.PartialOuterFrames != 1 ||
		report.Gateways[0].Modules != [2]uint64{0, 1} || pendingBytes != 0 {
		t.Fatalf("recovery crossed a TCP gap: %+v", report)
	}
}

func TestLongCaptureKeepsTCPAcrossFiles(t *testing.T) {
	const port = 5000
	const source, destination = "192.0.2.2", "192.0.2.1"
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	local := map[netip.Addr]bool{netip.MustParseAddr(destination): true}
	session := NewSession(port, local)
	wire := wrap(rFrame(0x12345607), 1)
	sequence := uint32(1000)
	for part := range 10 {
		var log bytes.Buffer
		writer, err := pcapgo.NewNgWriter(&log, layers.LinkTypeEthernet)
		if err != nil {
			t.Fatal(err)
		}
		send := func(seq uint32, dest uint16, second int, data []byte) {
			t.Helper()
			packet := tcpPacket(t, seq, false, dest, source, destination, data)
			info := gopacket.CaptureInfo{Timestamp: start.Add(time.Duration(second) * time.Second),
				CaptureLength: len(packet), Length: len(packet)}
			if err := writer.WritePacket(info, packet); err != nil {
				t.Fatal(err)
			}
		}
		if part != 0 {
			send(sequence+12, port, part*60, wire[12:])
			sequence += uint32(len(wire))
		}
		for second := range 59 {
			send(sequence, port, part*60+second, wire)
			sequence += uint32(len(wire))
		}
		send(sequence, port, part*60+59, wire[:12])
		// Packet on another TCP port must not extend the reported time range.
		send(sequence, port+1, 2000, wire)
		if err := writer.Flush(); err != nil {
			t.Fatal(err)
		}
		if err := session.ReadCapture(context.Background(), &log); err != nil {
			t.Fatal(err)
		}
	}
	report := session.Finish(0)
	if report.Gateways[0].Modules != [2]uint64{599, 0} || report.TCPGaps != 0 || report.PartialOuterFrames != 1 {
		t.Fatalf("cross-file packets were dropped or miscounted: %+v, %+v", report, report.Gateways)
	}
	if span := report.LastTCPPayload.Sub(report.FirstTCPPayload); span != 599*time.Second {
		t.Fatalf("target payload span = %v", span)
	}
}
