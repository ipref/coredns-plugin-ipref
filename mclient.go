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
	MSGMAX   = 64
	sockname = "/var/run/ipref-mapper.sock"
)

var conn *net.UnixConn
var msg [MSGMAX]byte
var id byte

var re_hexref *regexp.Regexp
var re_decref *regexp.Regexp
var re_dotref *regexp.Regexp

func compile_regex() {
	re_hexref = regexp.MustCompile(`^[0-9a-fA-F]+([-][0-9a-fA-F]+)+$`)
	re_decref = regexp.MustCompile(`^[0-9]+([,][0-9]+)*$`)
	re_dotref = regexp.MustCompile(`^([1-9]?[0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])([.]([1-9]?[0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]))+$`)
}

// parse reference
func parse_ref(sss string) ([]byte, error) {

	ref := make([]byte, 8, 8)
	var val uint64
	var err error

	// hex (max 16 bytes)

	if re_hexref.MatchString(sss) {
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
		for ii := reflen - hexlen/2; ii < reflen; ii++ {
			val, err := strconv.ParseUint(hexstr[ii+ii:ii+ii+2], 16, 8)
			if err != nil {
				return ref, err
			}
			ref[ii] = byte(val)
		}
		return ref, nil
	}

	// decimal (max 8 bytes)

	if re_decref.MatchString(sss) {
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

	if re_dotref.MatchString(sss) {
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

func encoded_address(ip net.IP, ref []byte) (net.IP, error) {

	var err error

	if conn == nil {
		conn, err = net.DialUnix("unixpacket", nil, &net.UnixAddr{sockname, "unixpacket"})
		if err != nil {
			conn = nil
			return net.IP{0, 0, 0, 0}, fmt.Errorf("cannot connect to mapper: %v", err)
		}
	}

	// header

	wlen := 4

	msg[0] = 0x42
	if id += 1; id == 255 {
		id = 1
	}
	msg[1] = id
	msg[2] = 0
	msg[3] = 0

	// ip

	iplen := len(ip)
	if iplen != 4 && iplen != 16 {
		return net.IP{0, 0, 0, 0}, fmt.Errorf("invalid IP length: %v", iplen)
	}

	copy(msg[wlen:], ip)
	wlen += iplen
	msg[2] = byte((iplen >> 2) << 4)

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

	err = conn.SetDeadline(time.Now().Add(time.Millisecond * 500))
	if err != nil {
		return net.IP{0, 0, 0, 0}, fmt.Errorf("cannot set mapper request deadline: %v", err)
	}

	// send request to mapper

	_, err = conn.Write(msg[:wlen])
	if err != nil {
		conn.Close()
		conn = nil
		return net.IP{0, 0, 0, 0}, fmt.Errorf("mapper request send error: %v", err)
	}

	// read response

	rlen, err := conn.Read(msg[:])
	if err != nil {
		conn.Close()
		conn = nil
		return net.IP{0, 0, 0, 0}, fmt.Errorf("mapper request receive error: %v", err)
	}

	if rlen < 2 {
		return net.IP{0, 0, 0, 0}, fmt.Errorf("mapper request no data received")
	}

	if msg[0] != 0x82 {
		return net.IP{0, 0, 0, 0}, fmt.Errorf("mapper request declined by mapper")
	}

	if rlen != int(msg[3])*4 {
		return net.IP{0, 0, 0, 0}, fmt.Errorf("mapper request malformed response")
	}

	if msg[1] != id {
		return net.IP{0, 0, 0, 0}, fmt.Errorf("mapper request response out of sequence")
	}

	ealen := int(msg[2]&0x0f) * 4

	if ealen != 4 && ealen != 16 {
		return net.IP{0, 0, 0, 0}, fmt.Errorf("invalid encoded address length: %v", ealen)
	}

	return msg[rlen-ealen : rlen], nil
}
