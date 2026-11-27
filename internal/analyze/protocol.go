package analyze

import (
	"bytes"
	"encoding/binary"
)

const (
	ethernetGateway          = 0x01
	ethernetHeartbeat        = 0x06
	encryptionHandshake      = 0x08
	encryptedEthernetGateway = 0x09
	encryptedCellularGateway = 0x0a
	plaintextEthernetGateway = 0x0b
	plaintextCellularGateway = 0x0c
	etheDownlink             = 0x02
)

// The length rules for C, L, R, TA and the observed TO/01/24 variant
// are shared with the positioning TCP recorder.
var cLengths = map[byte][2]int{
	1: {7, 0}, 2: {9, 0}, 3: {7, 17}, 4: {7, 0}, 5: {7, 17},
	6: {7, 2}, 8: {7, 19}, 9: {7, 19}, 10: {9, 2}, 12: {7, 19},
	13: {7, 2}, 14: {7, 2}, 33: {7, 0}, 34: {7, 2}, 37: {7, 19},
	38: {7, 19}, 39: {7, 19}, 40: {9, 2},
}

func sumOK(frame []byte, start int) bool {
	var sum byte
	for _, value := range frame[start : len(frame)-2] {
		sum += value
	}
	return sum == frame[len(frame)-2]
}

// Return the length and card record layout of a supported inner frame.
// A zero count is a recognized frame with no card record.
func innerLayout(b []byte) (size, checksum, offset, count, stride int, tail byte) {
	switch {
	case bytes.HasPrefix(b, []byte("TA")), bytes.HasPrefix(b, []byte("TO")):
		size = int(b[3]) + 5
		if b[0] == 'T' && b[1] == 'O' && b[2] == 1 && b[3] == 0x24 {
			// The longer TO variant uses its next byte as the length field.
			variantSize := int(b[4]) + 6
			if size > len(b) || b[size-1] != 'B' || !sumOK(b[:size], 2) {
				size = variantSize
			}
		}
		if size >= 19 {
			return size, 2, size - 11, 1, 4, 'B'
		}
	case b[0] == 'L' && b[1] >= 1 && b[1] <= 4:
		offset = 3 + 5*int(b[2])
		return offset + 10, 1, offset, 1, 4, 'A'
	case b[0] == 'R':
		size = 9 + 5*int(b[1])
		return size, 1, size - 7, 1, 4, 'A'
	case b[0] == 'C':
		if layout, ok := cLengths[b[3]]; ok {
			offset = 5 + layout[0]*int(b[4])
			return offset + 10 + layout[1], 1, offset, 1, 4, 'N'
		}
	case bytes.HasPrefix(b, []byte("HJ")):
		count = int(b[4])
		// A convergence gateway can bundle several card observations.
		switch b[3] {
		case 0:
			return 8 + 15*count, 2, 6, count, 15, 'E'
		case 1, 4:
			return 8 + 5*count, 2, 6, count, 5, 'E'
		case 2:
			return 8 + 5*count, 2, 6, 0, 0, 'E'
		case 3:
			return 8 + 13*count, 2, 6, 0, 0, 'E'
		}
	}
	return 0, 0, 0, 0, 0, 0
}

var ethe = []byte("ETHE")

type decoder struct {
	buffer []byte
	report *Report
}

func (d *decoder) feed(data []byte) {
	d.buffer = append(d.buffer, data...)
	for len(d.buffer) >= len(ethe) {
		start := bytes.Index(d.buffer, ethe)
		if start < 0 {
			start = len(d.buffer) - len(ethe) + 1
			d.report.UnframedBytes += uint64(start)
			d.buffer = d.buffer[start:]
			break
		}
		d.report.UnframedBytes += uint64(start)
		d.buffer = d.buffer[start:]
		if len(d.buffer) < 6 {
			break
		}
		size := int(binary.BigEndian.Uint16(d.buffer[4:6])) + 22
		if len(d.buffer) < size {
			break
		}
		frame := d.buffer[:size]
		switch {
		case frame[size-1] != 'M':
			d.report.BadOuterTail++
		case !sumOK(frame, 4):
			d.report.BadOuterChecksum++
		default:
			d.report.OuterFrames++
			d.report.readOuter(frame)
			d.buffer = d.buffer[size:]
			continue
		}
		d.report.BadOuterFrames++
		d.buffer = d.buffer[1:]
	}
	if len(d.buffer) == 0 {
		d.buffer = nil
	}
}

func (d *decoder) interrupt() {
	if len(d.buffer) > 0 &&
		(bytes.HasPrefix(ethe, d.buffer) || bytes.HasPrefix(d.buffer, ethe)) {
		d.report.PartialOuterFrames++
	}
	d.buffer = nil
}

func (r *Report) readOuter(frame []byte) {
	if frame[7] == etheDownlink {
		r.DownlinkOuterFrames++
		return
	}
	kind := frame[6]
	switch kind {
	case encryptionHandshake:
		r.HandshakeOuterFrames++
	case encryptedEthernetGateway, encryptedCellularGateway:
		r.EncryptedOuterFrames++
	default:
		payloadEnd := len(frame) - 14
		r.readPayload(kind, frame[payloadEnd:len(frame)-2], frame[8:payloadEnd])
	}
}

func (r *Report) readPayload(kind byte, gatewayID, payload []byte) {
	gateway := r.gateway(kind, gatewayID)
	if gateway == nil {
		return
	}
	for len(payload) >= 8 {
		size, checksum, offset, count, stride, tail := innerLayout(payload)
		if size == 0 || size > len(payload) {
			gateway.UnknownBytes++
			payload = payload[1:]
			continue
		}
		frame := payload[:size]
		if frame[size-1] == tail && sumOK(frame, checksum) {
			for i := 0; i < count; i++ {
				pos := offset + i*stride
				gateway.addCard(binary.BigEndian.Uint32(frame[pos : pos+4]))
			}
			payload = payload[size:]
			continue
		}
		if frame[size-1] == tail {
			gateway.BadInnerFrames++
		}
		gateway.UnknownBytes++
		payload = payload[1:]
	}
	gateway.UnknownBytes += uint64(len(payload))
}
