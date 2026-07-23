package snmp

import (
	"encoding/binary"
	"fmt"
)

// --- ASN.1 BER codec + OID helpers ---
//
// Pure, Agent-independent SNMP wire primitives: BER tag-length-value
// encode/decode, the Counter32/Gauge32/Counter64/TimeTicks/OID/integer
// encoders, the PDU field decoder, and the OID comparison helpers.
// Extracted verbatim from agent.go (#5661 modularity cohort).

// oidHasPrefix checks if oid starts with prefix.
func oidHasPrefix(oid, prefix []int) bool {
	if len(oid) < len(prefix) {
		return false
	}
	for i := range prefix {
		if oid[i] != prefix[i] {
			return false
		}
	}
	return true
}

// berEncodeCounter32 encodes a Counter32 value (unsigned 32-bit).
func berEncodeCounter32(val uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, val)
	// Strip leading zeros but keep at least one byte.
	// If high bit set, prepend zero for unsigned.
	for len(buf) > 1 && buf[0] == 0 {
		buf = buf[1:]
	}
	if buf[0]&0x80 != 0 {
		buf = append([]byte{0}, buf...)
	}
	return buf
}

// berEncodeGauge32 encodes a Gauge32 value (unsigned 32-bit).
func berEncodeGauge32(val uint32) []byte {
	return berEncodeCounter32(val) // same encoding
}

// berEncodeCounter64 encodes a Counter64 value (unsigned 64-bit).
func berEncodeCounter64(val uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, val)
	// Strip leading zeros but keep at least one byte.
	for len(buf) > 1 && buf[0] == 0 {
		buf = buf[1:]
	}
	// If high bit set, prepend zero for unsigned representation.
	if buf[0]&0x80 != 0 {
		buf = append([]byte{0}, buf...)
	}
	return buf
}

// --- BER encoding helpers ---

// tagTimeTicks is the ASN.1 application tag for TimeTicks (hundredths of a second).
const tagTimeTicks = 0x43

// berEncodeTLV encodes a tag-length-value triplet.
func berEncodeTLV(tag byte, value []byte) []byte {
	length := len(value)
	var buf []byte
	buf = append(buf, tag)
	buf = append(buf, berEncodeLength(length)...)
	buf = append(buf, value...)
	return buf
}

// berEncodeLength encodes a BER length field.
func berEncodeLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	// Multi-byte length.
	var lenBytes []byte
	l := length
	for l > 0 {
		lenBytes = append([]byte{byte(l & 0xff)}, lenBytes...)
		l >>= 8
	}
	return append([]byte{byte(0x80 | len(lenBytes))}, lenBytes...)
}

// berEncodeIntegerTLV encodes an integer as a complete TLV.
func berEncodeIntegerTLV(val int) []byte {
	return berEncodeTLV(tagInteger, berEncodeIntegerValue(val))
}

// berEncodeIntegerValue encodes an integer value (without tag/length).
func berEncodeIntegerValue(val int) []byte {
	if val == 0 {
		return []byte{0}
	}

	// Convert to big-endian bytes with proper sign handling.
	var bytes []byte
	if val > 0 {
		for v := val; v > 0; v >>= 8 {
			bytes = append([]byte{byte(v & 0xff)}, bytes...)
		}
		// If high bit set, prepend a zero byte (positive number must not look negative).
		if bytes[0]&0x80 != 0 {
			bytes = append([]byte{0}, bytes...)
		}
	} else {
		// Negative: two's complement encoding.
		for v := val; v < -1; v >>= 8 {
			bytes = append([]byte{byte(v & 0xff)}, bytes...)
		}
		if len(bytes) == 0 || bytes[0]&0x80 == 0 {
			bytes = append([]byte{0xff}, bytes...)
		}
	}
	return bytes
}

// berEncodeTimeTicks encodes a TimeTicks value (unsigned 32-bit integer).
func berEncodeTimeTicks(hundredths int) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(hundredths))
	// Strip leading zeros but keep at least one byte.
	for len(buf) > 1 && buf[0] == 0 {
		buf = buf[1:]
	}
	// TimeTicks is an unsigned APPLICATION integer: if the most-significant
	// content octet has its high bit set, prepend a 0x00 so the value is not
	// misdecoded as a negative signed INTEGER. This mirrors berEncodeCounter32 /
	// berEncodeGauge32 / berEncodeCounter64; without it a sysUpTime or v1/v2
	// link-trap timestamp at >= 0x80000000 hundredths (~248.5 days of uptime)
	// encodes as non-canonical/negative BER that strict managers reject (#4924).
	if buf[0]&0x80 != 0 {
		buf = append([]byte{0x00}, buf...)
	}
	return buf
}

// berEncodeOID encodes an OID value (without tag/length).
func berEncodeOID(oid []int) []byte {
	if len(oid) < 2 {
		return nil
	}
	// First two components are combined: first*40 + second.
	var encoded []byte
	encoded = append(encoded, byte(oid[0]*40+oid[1]))
	for i := 2; i < len(oid); i++ {
		encoded = append(encoded, berEncodeSubID(oid[i])...)
	}
	return encoded
}

// berEncodeSubID encodes a single OID sub-identifier using base-128 encoding.
func berEncodeSubID(val int) []byte {
	if val < 0x80 {
		return []byte{byte(val)}
	}
	var bytes []byte
	for v := val; v > 0; v >>= 7 {
		bytes = append([]byte{byte(v & 0x7f)}, bytes...)
	}
	// Set high bit on all but the last byte.
	for i := 0; i < len(bytes)-1; i++ {
		bytes[i] |= 0x80
	}
	return bytes
}

// berEncodeValue encodes a value with the given tag.
func berEncodeValue(tag byte, value []byte) []byte {
	return berEncodeTLV(tag, value)
}

// --- BER decoding helpers ---

// berDecodeHeader decodes a BER TLV header, returning the tag, the value bytes, and any error.
func berDecodeHeader(data []byte) (byte, []byte, error) {
	if len(data) < 2 {
		return 0, nil, fmt.Errorf("ber: data too short")
	}
	tag := data[0]
	length, lenBytes, err := berDecodeLength(data[1:])
	if err != nil {
		return 0, nil, err
	}
	headerLen := 1 + lenBytes
	if headerLen+length > len(data) {
		return 0, nil, fmt.Errorf("ber: value truncated (need %d, have %d)", headerLen+length, len(data))
	}
	return tag, data[headerLen : headerLen+length], nil
}

// berDecodeLength decodes a BER length field.
// Returns the length value and the number of bytes consumed.
func berDecodeLength(data []byte) (int, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("ber: empty length")
	}
	if data[0] < 0x80 {
		return int(data[0]), 1, nil
	}
	numBytes := int(data[0] & 0x7f)
	if numBytes == 0 || numBytes > 4 {
		return 0, 0, fmt.Errorf("ber: unsupported length encoding (%d bytes)", numBytes)
	}
	if len(data) < 1+numBytes {
		return 0, 0, fmt.Errorf("ber: length bytes truncated")
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(data[1+i])
	}
	return length, 1 + numBytes, nil
}

// berDecodeInteger decodes a BER INTEGER, returning the value and remaining bytes.
func berDecodeInteger(data []byte) (int, []byte, error) {
	if len(data) < 2 {
		return 0, nil, fmt.Errorf("ber: integer too short")
	}
	if data[0] != tagInteger {
		return 0, nil, fmt.Errorf("ber: expected INTEGER (0x02), got 0x%02x", data[0])
	}
	length, lenBytes, err := berDecodeLength(data[1:])
	if err != nil {
		return 0, nil, err
	}
	headerLen := 1 + lenBytes
	if headerLen+length > len(data) {
		return 0, nil, fmt.Errorf("ber: integer value truncated")
	}
	valBytes := data[headerLen : headerLen+length]
	val := 0
	// Sign-extend from first byte.
	if len(valBytes) > 0 && valBytes[0]&0x80 != 0 {
		val = -1
	}
	for _, b := range valBytes {
		val = (val << 8) | int(b)
	}
	return val, data[headerLen+length:], nil
}

// berDecodeOctetString decodes a BER OCTET STRING, returning the value and remaining bytes.
func berDecodeOctetString(data []byte) ([]byte, []byte, error) {
	if len(data) < 2 {
		return nil, nil, fmt.Errorf("ber: octet string too short")
	}
	if data[0] != tagOctetString {
		return nil, nil, fmt.Errorf("ber: expected OCTET STRING (0x04), got 0x%02x", data[0])
	}
	length, lenBytes, err := berDecodeLength(data[1:])
	if err != nil {
		return nil, nil, err
	}
	headerLen := 1 + lenBytes
	if headerLen+length > len(data) {
		return nil, nil, fmt.Errorf("ber: octet string truncated")
	}
	return data[headerLen : headerLen+length], data[headerLen+length:], nil
}

// berDecodeOID decodes the raw bytes of a BER-encoded OID value into integer components.
func berDecodeOID(data []byte) ([]int, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("ber: empty OID")
	}
	// First byte encodes first two components: first = byte/40, second = byte%40.
	oid := []int{int(data[0]) / 40, int(data[0]) % 40}
	i := 1
	for i < len(data) {
		val := 0
		for {
			if i >= len(data) {
				return nil, fmt.Errorf("ber: OID sub-identifier truncated")
			}
			val = (val << 7) | int(data[i]&0x7f)
			if data[i]&0x80 == 0 {
				i++
				break
			}
			i++
		}
		oid = append(oid, val)
	}
	return oid, nil
}

// decodePDUFields decodes the common PDU fields: request-id, error-status/non-repeaters,
// error-index/max-repetitions, and the varbind list of OIDs.
func decodePDUFields(data []byte) (requestID int, field2 int, field3 int, oids [][]int, err error) {
	// request-id
	requestID, rest, err := berDecodeInteger(data)
	if err != nil {
		return 0, 0, 0, nil, fmt.Errorf("request-id: %w", err)
	}

	// error-status or non-repeaters
	field2, rest, err = berDecodeInteger(rest)
	if err != nil {
		return 0, 0, 0, nil, fmt.Errorf("field2: %w", err)
	}

	// error-index or max-repetitions
	field3, rest, err = berDecodeInteger(rest)
	if err != nil {
		return 0, 0, 0, nil, fmt.Errorf("field3: %w", err)
	}

	// varbind list (SEQUENCE of SEQUENCE).
	if len(rest) == 0 {
		return requestID, field2, field3, nil, nil
	}
	tag, vbListBody, err := berDecodeHeader(rest)
	if err != nil || tag != tagSequence {
		return 0, 0, 0, nil, fmt.Errorf("varbind list: not a SEQUENCE")
	}

	// Decode each varbind (SEQUENCE { OID, value }).
	remaining := vbListBody
	for len(remaining) > 0 {
		tag, vbBody, err := berDecodeHeader(remaining)
		if err != nil || tag != tagSequence {
			return 0, 0, 0, nil, fmt.Errorf("varbind: not a SEQUENCE")
		}
		// Advance past this varbind in the remaining buffer.
		consumed := len(remaining) - len(vbBody)
		// We need to figure out total consumed length including value.
		// Re-decode to get the exact offset.
		vbTotalLen := berEncodedLen(remaining)
		if vbTotalLen <= 0 || vbTotalLen > len(remaining) {
			break
		}
		remaining = remaining[vbTotalLen:]
		_ = consumed // unused

		// Decode OID from varbind body.
		if len(vbBody) < 2 {
			continue
		}
		if vbBody[0] != tagObjectIdentifier {
			continue
		}
		oidLen, oidLenBytes, err := berDecodeLength(vbBody[1:])
		if err != nil {
			continue
		}
		oidHeaderLen := 1 + oidLenBytes
		if oidHeaderLen+oidLen > len(vbBody) {
			continue
		}
		oid, err := berDecodeOID(vbBody[oidHeaderLen : oidHeaderLen+oidLen])
		if err != nil {
			continue
		}
		oids = append(oids, oid)
	}

	return requestID, field2, field3, oids, nil
}

// berEncodedLen returns the total encoded length of a BER TLV at the start of data.
func berEncodedLen(data []byte) int {
	if len(data) < 2 {
		return -1
	}
	length, lenBytes, err := berDecodeLength(data[1:])
	if err != nil {
		return -1
	}
	return 1 + lenBytes + length
}

// --- OID comparison helpers ---

// oidEqual returns true if two OIDs are identical.
func oidEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// oidCompare compares two OIDs lexicographically.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
func oidCompare(a, b []int) int {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	for i := 0; i < minLen; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}
