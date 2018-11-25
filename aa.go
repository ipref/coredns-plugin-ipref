package ipref

import (
	"fmt"
	"net"
	"strings"

	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
	"github.com/miekg/unbound"
)

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
		return res, fmt.Errorf("no valid TXT records")
	}

	// parse AA embedded in TXT

	var ea net.IP
	rrs := make([]dns.RR, 0) // encoded addresses
	reason := fmt.Errorf("no TXT records with valid AA records")

	for _, rr := range res.Rr {

		hdr := rr.Header()

		if hdr.Rrtype != dns.TypeTXT || hdr.Class != dns.ClassINET {
			continue // paranoia
		}

		for _, txt := range rr.(*dns.TXT).Txt {

			// get IPREF address

			toks := strings.Fields(txt)
			if len(toks) != 2 || toks[0] != "AA" {
				continue
			}

			addr := strings.Split(toks[1], "+") // ipref address: ip + ref

			if len(addr) != 2 {
				reason = fmt.Errorf("Invalid IPREF address")
				continue
			}

			ref, err := parse_ref(addr[1])
			if err != nil {
				reason = fmt.Errorf("Invalid IPREF reference")
				continue
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
					ipres, err = ipr.t.Resolve(addr[0], dns_type, dns.ClassINET)
				case "udp":
					ipres, err = ipr.u.Resolve(addr[0], dns_type, dns.ClassINET)
				}

				if err != nil || ipres.Rcode != dns.RcodeSuccess || !ipres.HaveData || ipres.NxDomain {
					reason = fmt.Errorf("cannot resolve IPREF ip address")
					continue
				}

				// process ip resolution rr

				for _, iprr := range ipres.Rr {

					iphdr := iprr.Header()

					if iphdr.Rrtype != dns.TypeA || hdr.Class != dns.ClassINET {
						continue
					}

					ea, err = encoded_address(iprr.(*dns.A).A, ref)
					if err != nil {
						reason = err
						continue
					}

					aa := new(dns.A) // we return AA as A ipv4 only for now
					aa.A = ea
					aa.Hdr.Name = hdr.Name
					aa.Hdr.Rrtype = dns.TypeA
					aa.Hdr.Class = dns.ClassINET
					aa.Hdr.Ttl = hdr.Ttl
					aa.Hdr.Rdlength = uint16(len(aa.A))

					rrs = append(rrs, aa)
				}

			} else {

				ea, err = encoded_address(ip, ref)
				if err != nil {
					reason = err
					continue
				}

				aa := new(dns.A) // we return AA as A ipv4 only for now
				aa.A = ea
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
		return res, reason
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
