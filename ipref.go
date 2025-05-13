package ipref

import (
	"context"
	"fmt"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"strconv"
	"strings"
	"time"
)

var log = clog.NewWithPlugin("ipref")

type Ipref struct {
	from []string
	except []string
	upstream string

	m *MapperClient
	ea_ipver int
	gw_ipver int
	mapper_socket string

	Next plugin.Handler
}

func (ipr *Ipref) Stop() error {
	ipr.m.clear()
	return nil
}

// ServeDNS implements the plugin.Handler interface.
func (ipr *Ipref) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	if !ipr.match(state) {
		return plugin.NextOrFailure(ipr.Name(), ipr.Next, ctx, w, r)
	}
	start := time.Now()

	var err error
	res := new(dns.Msg)
	res.SetReply(r)
	res.Answer, err = ipr.resolve_aa(r)
	if err != nil {
		res.Rcode = dns.RcodeServerFailure
	}

	server := metrics.WithServer(ctx)
	RcodeCount.WithLabelValues(server, rcodeToString(uint16(res.Rcode))).Add(1)
	RequestDuration.WithLabelValues(server).Observe(time.Since(start).Seconds())

	if res.Rcode != dns.RcodeSuccess {
		return plugin.NextOrFailure(ipr.Name(), ipr.Next, ctx, w, r)
	}

	w.WriteMsg(res)
	return 0, nil
}

// Name implements the Handler interface.
func (ipr *Ipref) Name() string { return "ipref" }


func (ipr *Ipref) match(state request.Request) bool {
	for _, from := range ipr.from {
		if plugin.Name(from).Matches(state.Name()) {
			goto except
		}
	}
	return false
except:
	for _, except := range ipr.except {
		if plugin.Name(except).Matches(state.Name()) {
			return false
		}
	}
	return true
}

func (ipr *Ipref) upstreamResolve(qname string, rrtype uint16) (msg *dns.Msg, err error) {
	msg = new(dns.Msg)
	msg.SetQuestion(qname, rrtype)
	msg, err = dns.Exchange(msg, ipr.upstream)
	if err != nil {
		msg = nil
		return
	}
	if msg.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("%v", rcodeToString(uint16(msg.Rcode)))
	}
	return
}

func normalizeName(name string) string {
	name = strings.ToLower(dns.Name(name).String())
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

func rcodeToString(rcode uint16) string {
	str, ok := dns.RcodeToString[int(rcode)]
	if !ok {
		str = strconv.Itoa(int(rcode))
	}
	return str
}
