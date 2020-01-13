package ipref

import (
	"encoding/binary"
	"fmt"
	"github.com/ipref/ref"
	"net"
	"regexp"
	"time"
)

const (
	// v1 constants
	V1_SIG      = 0x11 // v1 signature
	V1_HDR_LEN  = 8
	V1_AREC_LEN = 4 + 4 + 4 + 8 + 8 // ea + ip + gw + ref.h + ref.l
	// v1 header offsets
	V1_VER      = 0
	V1_CMD      = 1
	V1_PKTID    = 2
	V1_RESERVED = 4
	V1_PKTLEN   = 6
	// v1 arec offsets
	V1_AREC_EA   = 0
	V1_AREC_IP   = 4
	V1_AREC_GW   = 8
	V1_AREC_REFH = 12
	V1_AREC_REFL = 20
	// v1 commands
	V1_MC_GET_EA = 7
	// v1 tlv types
	V1_TYPE_STRING = 4
	// v1 command mode, top two bits
	V1_DATA = 0x00
	V1_REQ  = 0x40
	V1_ACK  = 0x80
	V1_NACK = 0xC0
)

const (
	MSGMAX = ((V1_HDR_LEN + V1_AREC_LEN + 2 + 255 + 16) / 16) * 16 // round up to 16 byte boundary (304)
)

var be = binary.BigEndian

type MapperClient struct {
	sockname string
	conn     *net.UnixConn
	msgid    uint16

	re_hexref *regexp.Regexp
	re_decref *regexp.Regexp
	re_dotref *regexp.Regexp
}

func (m *MapperClient) init() {
	m.sockname = "/var/run/ipref-mapper.sock"
	m.msgid = uint16(time.Now().Unix() & 0xffff)
}

func (m *MapperClient) clear() {
	if m.conn != nil {
		m.conn.Close()
	}
}

func (ipr *Ipref) encoded_address(dnm string, gw net.IP, ref ref.Ref) (net.IP, error) {

	m := ipr.m

	if m.conn == nil {
		conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{m.sockname, "unixpacket"})
		if err != nil {
			return net.IP{0, 0, 0, 0}, fmt.Errorf("cannot connect to mapper: %v", err)
		}
		m.conn = conn
	}

	var msg [MSGMAX]byte
	var err error

	// header

	m.msgid += 1

	msg[V1_VER] = V1_SIG
	msg[V1_CMD] = V1_REQ | V1_MC_GET_EA
	be.PutUint16(msg[V1_PKTID:V1_PKTID+2], uint16(m.msgid))
	copy(msg[V1_RESERVED:V1_RESERVED+2], []byte{0, 0})

	// address record

	off := V1_HDR_LEN

	copy(msg[off+V1_AREC_EA:off+V1_AREC_EA+4], []byte{0, 0, 0, 0})
	copy(msg[off+V1_AREC_IP:off+V1_AREC_IP+4], []byte{0, 0, 0, 0})

	gwlen := len(gw)
	if gwlen != 4 && gwlen != 16 {
		return net.IP{0, 0, 0, 0}, fmt.Errorf("invalid GW address length: %v", gwlen)
	}
	copy(msg[off+V1_AREC_GW:off+V1_AREC_GW+4], gw)

	be.PutUint64(msg[off+V1_AREC_REFH:off+V1_AREC_REFH+8], ref.H)
	be.PutUint64(msg[off+V1_AREC_REFL:off+V1_AREC_REFL+8], ref.L)

	// dns name

	off += V1_AREC_LEN
	msglen := off

	dnmlen := len(dnm)
	if 0 < dnmlen && dnmlen < 256 { // should be true since DNS names are shorter than 255 chars
		msg[off] = V1_TYPE_STRING
		msg[off+1] = byte(dnmlen)
		copy(msg[off+2:], dnm)
		msglen += (dnmlen + 5) &^ 3
	}

	// set wait time for response

	err = m.conn.SetDeadline(time.Now().Add(time.Millisecond * 500))
	if err != nil {
		return net.IP{0, 0, 0, 0}, fmt.Errorf("cannot set mapper request deadline: %v", err)
	}

	// send request to mapper

	be.PutUint16(msg[V1_PKTLEN:V1_PKTLEN+2], uint16(msglen/4))

	_, err = m.conn.Write(msg[:msglen])
	if err != nil {
		m.conn.Close()
		m.conn = nil
		return net.IP{0, 0, 0, 0}, fmt.Errorf("map request send error: %v", err)
	}

	// read response

	rlen, err := m.conn.Read(msg[:])
	if err != nil {
		m.conn.Close()
		m.conn = nil
		return net.IP{0, 0, 0, 0}, fmt.Errorf("map request receive error: %v", err)
	}

	if rlen < V1_HDR_LEN {
		return net.IP{0, 0, 0, 0}, fmt.Errorf("response from mapper too short")
	}

	if msg[V1_VER] != V1_SIG {
		return net.IP{0, 0, 0, 0}, fmt.Errorf("response is not a v1 protocol")
	}

	if msg[V1_CMD] != V1_ACK|V1_MC_GET_EA {
		return net.IP{0, 0, 0, 0}, fmt.Errorf("map request declined by mapper")
	}

	if rlen != int(be.Uint16(msg[V1_PKTLEN:V1_PKTLEN+2])*4) {
		return net.IP{0, 0, 0, 0}, fmt.Errorf("incorrect packet length")
	}

	if be.Uint16(msg[V1_PKTID:V1_PKTID+2]) != m.msgid {
		return net.IP{0, 0, 0, 0}, fmt.Errorf("mapper response out of sequence")
	}

	off = V1_HDR_LEN
	return msg[off+V1_AREC_EA : off+V1_AREC_EA+4], nil
}
