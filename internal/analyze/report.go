package analyze

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"time"
)

type Gateway struct {
	ID             string     `json:"gateway_id"`
	MAC            string     `json:"gateway_mac,omitempty"`
	Address        string     `json:"reported_address,omitempty"`
	Channels       [16]uint64 `json:"channels"`
	Modules        [2]uint64  `json:"modules"`
	UniqueCards    int        `json:"unique_cards"`
	BadInnerFrames uint64     `json:"bad_inner_frames"`
	UnknownBytes   uint64     `json:"unknown_bytes"`
	cards          map[uint32]struct{}
}

type Report struct {
	Gateways           []*Gateway `json:"gateways"`
	TCPPackets         uint64     `json:"tcp_packets"`
	TCPGaps            uint64     `json:"tcp_gaps"`
	MissingTCPBytes    uint64     `json:"missing_tcp_bytes"`
	CaptureTruncated   uint64     `json:"capture_truncated"`
	CaptureDropped     uint64     `json:"capture_dropped"`
	OuterFrames        uint64     `json:"outer_frames"`
	BadOuterFrames     uint64     `json:"bad_outer_frames"`
	PartialOuterFrames uint64     `json:"partial_outer_frames"`
	UnframedBytes      uint64     `json:"unframed_bytes"`
	UnsupportedPackets uint64     `json:"unsupported_packets"`
	FirstTCPPayload    time.Time  `json:"first_tcp_payload,omitzero"`
	LastTCPPayload     time.Time  `json:"last_tcp_payload,omitzero"`
	byID               map[string]*Gateway
}

func newReport() *Report {
	return &Report{Gateways: []*Gateway{}, byID: make(map[string]*Gateway)}
}

func (r *Report) gateway(kind byte, raw []byte) *Gateway {
	id, mac, address := strings.ToUpper(hex.EncodeToString(raw)), "", ""
	if id == "000000000000000000000000" || id == "555555555555555555555555" || id == "FFFFFFFFFFFFFFFFFFFFFFFF" {
		return nil
	}
	key := id
	if kind == 1 || kind == 6 {
		mac = fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", raw[6], raw[7], raw[8], raw[9], raw[10], raw[11])
		if mac != "00:00:00:00:00:00" && mac != "FF:FF:FF:FF:FF:FF" {
			key = mac
		} else {
			mac = ""
		}
		ip, _ := netip.AddrFromSlice(raw[:4])
		address = netip.AddrPortFrom(ip, binary.BigEndian.Uint16(raw[4:6])).String()
	}
	gateway := r.byID[key]
	if gateway == nil {
		gateway = &Gateway{ID: id, MAC: mac, Address: address, cards: make(map[uint32]struct{})}
		r.byID[key] = gateway
		r.Gateways = append(r.Gateways, gateway)
	}
	return gateway
}

func (g *Gateway) addCard(id uint32) {
	channel := id % 16
	g.Channels[channel]++
	g.Modules[channel/8]++
	g.cards[id] = struct{}{}
}

func (r *Report) snapshot() *Report {
	result := *r
	result.Gateways = make([]*Gateway, 0, len(r.Gateways))
	for _, gateway := range r.Gateways {
		copy := *gateway
		copy.UniqueCards = len(gateway.cards)
		copy.cards = nil
		result.Gateways = append(result.Gateways, &copy)
	}
	sort.Slice(result.Gateways, func(i, j int) bool { return result.Gateways[i].ID < result.Gateways[j].ID })
	result.byID = nil
	return &result
}

func ReadStream(reader io.Reader) (*Report, error) {
	report := newReport()
	stream := decoder{report: report}
	buffer := make([]byte, 64<<10)
	for {
		n, err := reader.Read(buffer)
		stream.feed(buffer[:n])
		if err == io.EOF {
			stream.interrupt()
			return report.snapshot(), nil
		}
		if err != nil {
			return nil, err
		}
	}
}
