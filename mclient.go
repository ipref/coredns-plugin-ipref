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
	MQP_PING    = 1
	MQP_MAP_EA  = 2
	MQP_INFO_AA = 3
	MSGMAX      = 320 // 255 + 1 + 16 + 16 + 16 + 4 = 308 rounded up to 16 byte boundary
)

var be = binary.BigEndian

type MapperClient struct {
	sockname string
	conn     *net.UnixConn
	msgid    byte

	re_hexref *regexp.Regexp
	re_decref *regexp.Regexp
	re_dotref *regexp.Regexp
}

func (m *MapperClient) init() {
	m.sockname = "/var/run/ipref-mapper.sock"
	m.msgid = byte(time.Now().Unix() & 0xff)
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
	wlen := 4

	msg[0] = 0x40 + MQP_MAP_EA
	msg[1] = m.msgid
	msg[2] = 0
	msg[3] = 0

	// dnm

	dnmlen := len(dnm)
	if dnmlen > 255 {
		return net.IP{0, 0, 0, 0}, fmt.Errorf("invalid domain name (too long): %v", dnm)
	}
	msg[4] = byte(dnmlen)
	copy(msg[5:], dnm)
	wlen += (dnmlen + 4) &^ 3
	for ii := 5 + dnmlen; ii < wlen; ii++ {
		msg[ii] = 0 // pad with zeros
	}

	// gw

	gwlen := len(gw)
	if gwlen != 4 && gwlen != 16 {
		return net.IP{0, 0, 0, 0}, fmt.Errorf("invalid GW address length: %v", gwlen)
	}

	copy(msg[wlen:], gw)
	wlen += gwlen
	msg[2] = byte((gwlen >> 2) << 4)

	// ref

	if ref.H != 0 {
		be.PutUint64(msg[wlen:wlen+8], ref.H)
		wlen += 8
	}

	be.PutUint64(msg[wlen:wlen+8], ref.L)
	wlen += 8

	msg[3] = byte(wlen) / 4

	// Don't wait more than half a second

	err = m.conn.SetDeadline(time.Now().Add(time.Millisecond * 500))
	if err != nil {
		return net.IP{0, 0, 0, 0}, fmt.Errorf("cannot set mapper request deadline: %v", err)
	}

	// send request to mapper

	_, err = m.conn.Write(msg[:wlen])
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

	if rlen < 4 {
		return net.IP{0, 0, 0, 0}, fmt.Errorf("response from mapper too short")
	}

	if msg[0] != 0x80+MQP_MAP_EA {
		return net.IP{0, 0, 0, 0}, fmt.Errorf("map request declined by mapper")
	}

	if rlen != int(msg[3])*4 {
		return net.IP{0, 0, 0, 0}, fmt.Errorf("malformed response from mapper")
	}

	if msg[1] != m.msgid {
		return net.IP{0, 0, 0, 0}, fmt.Errorf("mapper response out of sequence")
	}

	ealen := int(msg[2]&0x0f) * 4

	if ealen != 4 && ealen != 16 {
		return net.IP{0, 0, 0, 0}, fmt.Errorf("invalid encoded address length: %v", ealen)
	}

	return msg[rlen-ealen : rlen], nil
}
