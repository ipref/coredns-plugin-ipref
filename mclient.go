package ipref

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	MSGMAX = 320 // 255 + 1 + 16 + 16 + 16 + 4 = 308 rounded up to 16 byte boundary
)

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
	m.re_hexref = regexp.MustCompile(`^[0-9a-fA-F]+([-][0-9a-fA-F]+)+$`)
	m.re_decref = regexp.MustCompile(`^[0-9]+([,][0-9]+)*$`)
	m.re_dotref = regexp.MustCompile(`^([1-9]?[0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])([.]([1-9]?[0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]))+$`)
}

func (m *MapperClient) clear() {
	if m.conn != nil {
		m.conn.Close()
	}
}

// parse reference
func (ipr *Ipref) parse_ref(sss string) ([]byte, error) {

	m := ipr.m
	ref := make([]byte, 8, 8)
	var val uint64
	var err error

	// hex (max 16 bytes)

	if m.re_hexref.MatchString(sss) {

		hexstr := strings.Replace(sss, "-", "", -1)
		hexlen := len(hexstr)
		if hexlen > 32 {
			hexstr = hexstr[hexlen-32:]
			hexlen = 32
		}
		if hexlen > 16 {
			ref = make([]byte, 16, 16)
		}
		if (hexlen & 0x1) != 0 {
			hexstr = "0" + hexstr
			hexlen++
		}
		reflen := len(ref)
		for ii := 0; ii < hexlen/2; ii++ {
			val, err := strconv.ParseUint(hexstr[ii+ii:ii+ii+2], 16, 8)
			if err != nil {
				return ref, err
			}
			ref[ii+reflen-hexlen/2] = byte(val)
		}
		return ref, nil
	}

	// decimal (max 8 bytes)

	if m.re_decref.MatchString(sss) {

		decstr := strings.Replace(sss, ",", "", -1)
		val, err = strconv.ParseUint(decstr, 10, 64)
		if err != nil {
			return ref, err
		}
		for ii := 7; val != 0; val >>= 8 {
			ref[ii] = byte(val & 0xff)
			ii--
		}
		return ref, nil
	}

	// dotted decimal (max 16 bytes)

	if m.re_dotref.MatchString(sss) {

		dotstr := strings.Split(sss, ".")
		dotlen := len(dotstr)
		if dotlen > 16 {
			dotstr = dotstr[dotlen-16:]
			dotlen = 16
		}
		if dotlen > 8 {
			ref = make([]byte, 16, 16)
		}
		reflen := len(ref)
		for ii := reflen - dotlen; ii < reflen; ii++ {
			val, err := strconv.ParseUint(dotstr[ii], 10, 8)
			if err != nil {
				return ref, err
			}
			ref[ii] = byte(val)
		}
		return ref, nil
	}

	return ref, fmt.Errorf("invalid reference format")
}

func (ipr *Ipref) encoded_address(dnm string, gw net.IP, ref []byte) (net.IP, error) {

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

	wlen := 4

	msg[0] = 0x42
	if m.msgid += 1; m.msgid == 255 {
		m.msgid = 1
	}
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

	reflen := len(ref)
	if reflen > 16 {
		return net.IP{0, 0, 0, 0}, fmt.Errorf("invalid reference length: %v", reflen)
	}

	if reflen < 8 {
		for ii := 8 - reflen; ii > 0; ii-- {
			msg[wlen] = 0
			wlen++
		}
	} else if reflen == 8 {
	} else {
		for ii := 16 - reflen; ii > 0; ii-- {
			msg[wlen] = 0
			wlen++
		}
	}
	copy(msg[wlen:], ref)
	wlen += reflen
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

	if msg[0] != 0x82 {
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
