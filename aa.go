package unbound

import (
	"fmt"
	"net"
	"strings"

	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
	"github.com/miekg/unbound"
)

// pretty print result
func pp_res(res *unbound.Result) {

	fmt.Printf("result.for:    %v %v %v\n", res.Qname, res.Qtype, res.Qclass)

	fmt.Printf("result.Data:   [") // Data [][]byte -- Slice of rdata items formed from the reply
	space := ""
	for _, item := range res.Data {
		if res.Qtype == dns.TypeTXT {
			fmt.Printf("%v(%v)%v", space, item[0], string(item[1:]))
		} else {
			fmt.Printf("%v%v", space, item)
		}
		space = "  "
	}
	fmt.Printf("]\n")

	fmt.Printf("result.RR:     %v\n", res.Rr) // RR []dns.RR -- The RR encoded from Data, Qclass, Qtype, Qname and Ttl

	//fmt.Printf("result.AnsPkt: \n%v", res.AnswerPacket) //AnswerPacket *dns.Msg -- Full answer packet

	fmt.Printf("result.ret:    Rcode(%v)  HaveData(%v)  NxDomain(%v)  Secure(%v)  Bogus(%v)  why(%v)\n",
		res.Rcode, res.HaveData, res.NxDomain, res.Secure, res.Bogus, res.WhyBogus)
}

// allocate encoded address to an IPREF address
func encoded_address([]string) string {
	return "10.252.253.254"
}

// resolve AA query (emulated with TXT for now)
func (u *Unbound) resolve_aa(state request.Request) (*unbound.Result, error) {

	var res *unbound.Result
	var err error

	// resolve TXT

	switch state.Proto() {
	case "tcp":
		res, err = u.t.Resolve(state.QName(), dns.TypeTXT, dns.ClassINET)
	case "udp":
		res, err = u.u.Resolve(state.QName(), dns.TypeTXT, dns.ClassINET)
	}

	if err != nil || res.Rcode != dns.RcodeSuccess || !res.HaveData || res.NxDomain {
		return res, err
	}

	// parse AA embedded in TXT

	var aa string

	for _, item := range res.Data {
		if len(item) == 0 {
			continue
		}
		aa = string(item[1:])
		break // for now we allow only one
	}

	if len(aa) == 0 {
		return res, fmt.Errorf("TXT resolved successfully but no AA records")
	}

	toks := strings.Fields(aa)
	if len(toks) != 2 || toks[0] != "AA" {
		return res, fmt.Errorf("Invalid AA record")
	}

	addr := strings.Split(toks[1], "+") // ipref address: ip + ref

	if len(addr) != 2 {
		return res, fmt.Errorf("Invalid AA format")
	}

	// resolve IP portion of IPREF address if necessary

	if ip := net.ParseIP(addr[0]); ip == nil {

		var ipres *unbound.Result

		dns_type := dns.TypeA
		if strings.Index(addr[0], ".") < 0 {
			dns_type = dns.TypeAAAA
		}

		switch state.Proto() {
		case "tcp":
			ipres, err = u.t.Resolve(addr[0], dns_type, dns.ClassINET)
		case "udp":
			ipres, err = u.u.Resolve(addr[0], dns_type, dns.ClassINET)
		}

		if err != nil || ipres.Rcode != dns.RcodeSuccess || !ipres.HaveData || ipres.NxDomain {
			return ipres, err
		}

		addr[0] = ""
		for _, item := range ipres.Data {
			if len(item) == 0 {
				continue
			}
			addr[0] = net.IP(item).String()
			break // for now we allow only one
		}
		if len(addr[0]) == 0 {
			return ipres, fmt.Errorf("cannot resolve IP portion of IPREF address")
		}
	}

	// get encoded address

	ea_str := encoded_address(addr)
	if len(ea_str) == 0 {
		return res, fmt.Errorf("cannot allocate encoded address to IPREF address")
	}

	// compose result, replace TXT result with generated A result

	ea_bytes := net.ParseIP(ea_str).To4()

	res.Data[0] = ea_bytes

	res_rr := res.Rr[0]
	ix := strings.LastIndex(res_rr, "TXT")
	if ix < 0 {
		return res, fmt.Errorf("inconsistent result RR")
	}
	res.Rr[0] = res_rr[:ix] + "A\t" + ea_str
	res.AnswerPacket.Answer[0] = res.Rr[0]

	return res, nil
}
