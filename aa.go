package ipref

import (
	"errors"
	"fmt"
	. "github.com/ipref/common"
	"github.com/miekg/dns"
	"net"
	"strings"
)

var UnsupportedRRType = errors.New("unsupported RR type")
var NoAARecordsFound = errors.New("no valid AA records found")

// resolve AA query (emulated with TXT for now)
func (ipr *Ipref) resolve_aa(req *dns.Msg) ([]dns.RR, error) {

	if len(req.Question) != 1 {
		return nil, fmt.Errorf("expected exactly one question")
	}
	q := req.Question[0]
	if q.Qclass != dns.ClassINET || (q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA) {
		return nil, UnsupportedRRType
	}
	name := normalizeName(q.Name)

	// resolve TXT

	upRes, err := ipr.upstreamResolve(name, dns.TypeTXT)
	if err != nil {
		log.Debugf("upstream server error: %v", err)
		return nil, err
	}

	// parse AA embedded in TXT

	var ea IP
	answer := make([]dns.RR, 0) // encoded addresses

	for _, rr := range upRes.Answer {

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
				log.Debugf("invalid AA record: '%v'", txt)
				continue
			}

			addr[0] = strings.TrimSpace(addr[0])
			addr[1] = strings.TrimSpace(addr[1])

			ref, err := ParseRef(addr[1])
			if err != nil {
				log.Debugf("invalid AA record: '%v'", txt)
				continue
			}

			// resolve GW portion of IPREF address if necessary

			var gw IP
			if gw, err = ParseIP(addr[0]); err != nil {

				dns_type := dns.TypeA
				if ipr.gw_ipver == 6 {
					dns_type = dns.TypeAAAA
				}
				gwname := normalizeName(addr[0])
				var gwres *dns.Msg
				gwres, err = ipr.upstreamResolve(gwname, dns_type)
				if err != nil {
					log.Debugf("error resolving domain in AA record: '%v'", gwname)
					continue
				}

				// process gw resolution rr

				for _, gwrr := range gwres.Answer {

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

					ea, err = ipr.encoded_address(name, gw, ref)
					if err != nil {
						log.Debugf("error getting encoded address for %v + %v: %v", gw, ref, err)
						continue
					}

					answer = append(answer, createRR(hdr, ea))
				}

			} else {

				if gw.Ver() != ipr.gw_ipver {
					continue
				}

				ea, err = ipr.encoded_address(name, gw, ref)
				if err != nil {
					log.Debugf("error getting encoded address for %v + %v: %v", gw, ref, err)
					continue
				}

				answer = append(answer, createRR(hdr, ea))
			}
		}
	}

	if len(answer) == 0 {
		return nil, NoAARecordsFound
	}
	return answer, nil
}

// create an A or AAAA from an existing RR header and an IP
func createRR(hdr *dns.RR_Header, ip IP) (rr dns.RR) {
	nip := net.ParseIP(ip.String())
	if ip.Is4() {
		a := new(dns.A)
		a.A = nip
		a.Hdr.Rrtype = dns.TypeA
		rr = a
	} else {
		aaaa := new(dns.AAAA)
		aaaa.AAAA = nip
		aaaa.Hdr.Rrtype = dns.TypeAAAA
		rr = aaaa
	}
	rr.Header().Name = hdr.Name
	rr.Header().Class = dns.ClassINET
	rr.Header().Ttl = hdr.Ttl
	rr.Header().Rdlength = uint16(len(nip))
	return
}
