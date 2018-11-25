package ipref

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
//var fake_ea byte

func encoded_address(ip net.IP, ref string) net.IP {

	//	if fake_ea++; fake_ea == 255 {
	//		fake_ea = 1
	//	}

	ea := net.IP{10, 252, 253, 1}

	return ea
}

// resolve AA query (emulated with TXT for now)
func (ipr *Ipref) resolve_aa(state request.Request) (*unbound.Result, error) {

	var res *unbound.Result
	var err error

	// resolve TXT

	switch state.Proto() {
	case "tcp":
		res, err = ipr.t.Resolve(state.QName(), dns.TypeTXT, dns.ClassINET)
	case "udp":
		res, err = ipr.u.Resolve(state.QName(), dns.TypeTXT, dns.ClassINET)
	}

	if err != nil || res.Rcode != dns.RcodeSuccess || !res.HaveData || res.NxDomain {
		return res, fmt.Errorf("no TXT records, containing embeded AA records, found")
	}

	// parse AA embedded in TXT

	rrs := make([]dns.RR, 0) // encoded addresses

	for _, rr := range res.Rr {

		hdr := rr.Header()

		if hdr.Rrtype != dns.TypeTXT || hdr.Class != dns.ClassINET {
			continue
		}

		for _, txt := range rr.(*dns.TXT).Txt {

			// get IPREF address

			toks := strings.Fields(txt)
			if len(toks) != 2 || toks[0] != "AA" {
				continue //return res, fmt.Errorf("Invalid AA record")
			}

			addr := strings.Split(toks[1], "+") // ipref address: ip + ref

			if len(addr) != 2 {
				continue // return res, fmt.Errorf("Invalid AA format")
			}

			ref := addr[1] // string for now, but we should parse it to a Ref type

			// resolve IP portion of IPREF address if necessary

			if ip := net.ParseIP(addr[0]); ip == nil {

				var ipres *unbound.Result

				dns_type := dns.TypeA
				if strings.Index(addr[0], ".") < 0 {
					dns_type = dns.TypeAAAA
				}

				switch state.Proto() {
				case "tcp":
					ipres, err = ipr.t.Resolve(addr[0], dns_type, dns.ClassINET)
				case "udp":
					ipres, err = ipr.u.Resolve(addr[0], dns_type, dns.ClassINET)
				}

				if err != nil || ipres.Rcode != dns.RcodeSuccess || !ipres.HaveData || ipres.NxDomain {
					continue // return ipres, err
				}

				// process ip resolution rr

				for _, iprr := range ipres.Rr {

					iphdr := iprr.Header()

					if iphdr.Rrtype != dns.TypeA || hdr.Class != dns.ClassINET {
						continue
					}

					aa := new(dns.A) // we return AA as A ipv4 only for now
					aa.A = encoded_address(iprr.(*dns.A).A, ref)
					aa.Hdr.Name = hdr.Name
					aa.Hdr.Rrtype = dns.TypeA
					aa.Hdr.Class = dns.ClassINET
					aa.Hdr.Ttl = hdr.Ttl
					aa.Hdr.Rdlength = uint16(len(aa.A))

					rrs = append(rrs, aa)
				}

			} else {

				aa := new(dns.A) // we return AA as A ipv4 only for now
				aa.A = encoded_address(ip, ref)
				aa.Hdr.Name = hdr.Name
				aa.Hdr.Rrtype = dns.TypeA
				aa.Hdr.Class = dns.ClassINET
				aa.Hdr.Ttl = hdr.Ttl
				aa.Hdr.Rdlength = uint16(len(aa.A))

				rrs = append(rrs, aa)
			}
		}
	}

	if len(rrs) == 0 {
		return res, fmt.Errorf("TXT resolved successfully but no AA records")
	}

	// compose result, replace TXT result with generated A result

	res.Qtype = dns.TypeA
	res.Rr = rrs
	res.AnswerPacket.Answer = rrs
	res.AnswerPacket.Question = state.Req.Question

	res.Data = make([][]byte, 0)
	for _, rr := range rrs {
		res.Data = append(res.Data, rr.(*dns.A).A)
	}

	return res, nil
}
