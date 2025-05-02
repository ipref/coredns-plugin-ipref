package ipref

import (
	"fmt"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	. "github.com/ipref/common"
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

	var ea IP
	rrs := make([]dns.RR, 0) // encoded addresses
	var reason error

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

			var gw IP
			if gw, err = ParseIP(addr[0]); err != nil {

				var gwres *unbound.Result

				dns_type := dns.TypeA
				if ipr.gw_ipver == 6 {
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

					if hdr.Class != dns.ClassINET {
						continue
					}
					if gwhdr.Rrtype == dns.TypeA {
						gw = MustParseIP(gwrr.(*dns.A).A.String())
					} else if gwhdr.Rrtype == dns.TypeAAAA {
						gw = MustParseIP(gwrr.(*dns.AAAA).AAAA.String())
					} else {
						continue
					}

					if gw.Ver() != ipr.gw_ipver {
						continue
					}

					ea, err = ipr.encoded_address(state.QName(), gw, ref)
					if err != nil {
						reason = err
						continue
					}

					rrs = append(rrs, hdr_and_ip_to_rr(hdr, ea))
				}

			} else {

				if gw.Ver() != ipr.gw_ipver {
					continue
				}

				ea, err = ipr.encoded_address(state.QName(), gw, ref)
				if err != nil {
					reason = err
					continue
				}

				rrs = append(rrs, hdr_and_ip_to_rr(hdr, ea))
			}
		}
	}

	if len(rrs) == 0 {
		if reason == nil {
			reason = fmt.Errorf("no TXT records with valid AA records")
		} else {
			clog.Errorf("ipref mapper: %v", reason)
		}
		return res, reason
	}

	// compose result, replace TXT result with generated A result

	res.Qtype = dns.TypeA
	res.Rr = rrs
	res.AnswerPacket.Answer = rrs
	res.AnswerPacket.Question = state.Req.Question

	res.Data = make([][]byte, 0)
	for _, rr := range rrs {
		var ip []byte
		switch r := rr.(type) {
		case *dns.A:
			ip = r.A
		case *dns.AAAA:
			ip = r.AAAA
		default:
			panic("unexpected")
		}
		res.Data = append(res.Data, ip)
	}

	return res, nil
}

// create an A or AAAA from an existing RR header and an IP
func hdr_and_ip_to_rr(hdr *dns.RR_Header, ip IP) dns.RR {

	nip := net.ParseIP(ip.String())
	if ip.Is4() {
		rr := new(dns.A)
		rr.A = nip
		rr.Hdr.Name = hdr.Name
		rr.Hdr.Rrtype = dns.TypeA
		rr.Hdr.Class = dns.ClassINET
		rr.Hdr.Ttl = hdr.Ttl
		rr.Hdr.Rdlength = uint16(len(rr.A))
		return rr
	} else {
		rr := new(dns.AAAA)
		rr.AAAA = nip
		rr.Hdr.Name = hdr.Name
		rr.Hdr.Rrtype = dns.TypeAAAA
		rr.Hdr.Class = dns.ClassINET
		rr.Hdr.Ttl = hdr.Ttl
		rr.Hdr.Rdlength = uint16(len(rr.AAAA))
		return rr
	}
}
