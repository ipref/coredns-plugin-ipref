package ipref

import (
	"fmt"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/ipref/ref"
	"github.com/miekg/dns"
	"github.com/miekg/unbound"
	"net"
	"strings"
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

			if !strings.HasPrefix(txt, "AA ") {
				continue
			}
			addr := strings.Split(txt[3:], "+")

			if len(addr) != 2 {
				reason = fmt.Errorf("invalid IPREF address")
				continue
			}

			addr[0] = strings.TrimSpace(addr[0])
			addr[1] = strings.TrimSpace(addr[1])

			ref, err := ref.Parse(addr[1])
			if err != nil {
				reason = fmt.Errorf("invalid IPREF reference: %v %v", addr[1], err)
				continue
			}

			// resolve GW portion of IPREF address if necessary

			if gw := net.ParseIP(addr[0]); gw == nil {

				var gwres *unbound.Result

				dns_type := dns.TypeA
				if strings.Index(addr[0], ".") < 0 {
					dns_type = dns.TypeAAAA
				}

				switch state.Proto() {
				case "tcp":
					gwres, err = ipr.t.Resolve(addr[0], dns_type, dns.ClassINET)
				case "udp":
					gwres, err = ipr.u.Resolve(addr[0], dns_type, dns.ClassINET)
				}

				if err != nil || gwres.Rcode != dns.RcodeSuccess || !gwres.HaveData || gwres.NxDomain {
					reason = fmt.Errorf("cannot resolve IPREF gw address")
					continue
				}

				// process gw resolution rr

				for _, gwrr := range gwres.Rr {

					gwhdr := gwrr.Header()

					if gwhdr.Rrtype != dns.TypeA || hdr.Class != dns.ClassINET {
						continue
					}

					ea, err = ipr.encoded_address(state.QName(), gwrr.(*dns.A).A, ref)
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

				ea, err = ipr.encoded_address(state.QName(), gw, ref)
				if err != nil {
					reason = err
					continue
				}

				aa := new(dns.A) // we return AA as A ipv4 for now
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
		clog.Errorf("ipref mapper: %v", reason)
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
