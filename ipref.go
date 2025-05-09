package ipref

import (
	"context"
	"fmt"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/miekg/unbound"
	"strconv"
)

var log = clog.NewWithPlugin("ipref")

// Ipref is a plugin that resolves requests using libunbound.
type Ipref struct {
	u *unbound.Unbound
	t *unbound.Unbound
	m *MapperClient
	ea_ipver int
	gw_ipver int
	mapper_socket string

	from   []string
	except []string

	Next plugin.Handler
}

var options = map[string]string{
	// options for unbound, see unbound.conf(5).
	"msg-cache-size":   "0",
	"rrset-cache-size": "0",

	"ea-ipver": "4",
	"gw-ipver": "4",

	"mapper": "/var/run/ipref-mapper.sock",
}

// New returns a pointer to an initialzed Ipref.
func New() *Ipref {
	udp := unbound.New()
	tcp := unbound.New()
	tcp.SetOption("tcp-upstream:", "yes")

	ipr := &Ipref{u: udp, t: tcp}

	for k, v := range options {
		if err := ipr.setOption(k, v); err != nil {
			log.Warningf("Could not set option: %s", err)
		}
	}

	ipr.m = &MapperClient{}
	ipr.m.init()

	return ipr
}

// Stop stops unbound and cleans up the memory used.
func (ipr *Ipref) Stop() error {
	ipr.u.Destroy()
	ipr.t.Destroy()
	ipr.m.clear()
	return nil
}

// setOption sets option k to value v in ipr.
func (ipr *Ipref) setOption(k, v string) error {
	switch k {
	case "msg-cache-size", "rrset-cache-size":

		// Add ":" as unbound expects it
		k += ":"
		// Set for both udp and tcp handlers, return the error from the latter.
		ipr.u.SetOption(k, v)
		err := ipr.t.SetOption(k, v)
		if err != nil {
			return fmt.Errorf("failed to set option %q with value %q: %s", k, v, err)
		}
		return nil

	case "ea-ipver":
		var err error
		ipr.ea_ipver, err = strconv.Atoi(v)
		if err != nil {
			return err
		}
		if ipr.ea_ipver != 4 && ipr.ea_ipver != 6 {
			return fmt.Errorf("invalid ea ip version: %s", v)
		}
		return nil

	case "gw-ipver":
		var err error
		ipr.gw_ipver, err = strconv.Atoi(v)
		if err != nil {
			return err
		}
		if ipr.gw_ipver != 4 && ipr.gw_ipver != 6 {
			return fmt.Errorf("invalid gw ip version: %s", v)
		}
		return nil

	case "mapper":
		ipr.mapper_socket = v
		return nil

	default:
		return fmt.Errorf("unrecognized option: %s", k)
	}
}

// config reads the file f and sets unbound configuration
func (ipr *Ipref) config(f string) error {
	var err error

	err = ipr.u.Config(f)
	if err != nil {
		return fmt.Errorf("failed to read config file (%s) UDP context: %s", f, err)
	}

	err = ipr.t.Config(f)
	if err != nil {
		return fmt.Errorf("failed to read config file (%s) TCP context: %s", f, err)
	}
	return nil
}

// ServeDNS implements the plugin.Handler interface.
func (ipr *Ipref) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	if !ipr.match(state) {
		return plugin.NextOrFailure(ipr.Name(), ipr.Next, ctx, w, r)
	}

	var res *unbound.Result
	var err error

	switch {

	case state.QClass() == dns.ClassINET && (state.QType() == dns.TypeA || state.QType() == dns.TypeAAAA):

		if res, err = ipr.resolve_aa(state); err == nil { // try AA first
			break
		}

		fallthrough

	default:

		return dns.RcodeServerFailure, err
	}

	rcode := dns.RcodeServerFailure
	if err == nil {
		rcode = res.AnswerPacket.Rcode
	}
	rc, ok := dns.RcodeToString[rcode]
	if !ok {
		rc = strconv.Itoa(rcode)
	}

	server := metrics.WithServer(ctx)
	RcodeCount.WithLabelValues(server, rc).Add(1)
	RequestDuration.WithLabelValues(server).Observe(res.Rtt.Seconds())

	if err != nil {
		return dns.RcodeServerFailure, err
	}

	// If the client *didn't* set the opt record, and specifically not the DO bit,
	// strip this from the reply (unbound default to setting DO).
	if !state.Do() {
		// technically we can still set bufsize and fluff, for now remove the entire OPT record.
		for i := 0; i < len(res.AnswerPacket.Extra); i++ {
			rr := res.AnswerPacket.Extra[i]
			if _, ok := rr.(*dns.OPT); ok {
				res.AnswerPacket.Extra = append(res.AnswerPacket.Extra[:i], res.AnswerPacket.Extra[i+1:]...)
				break // TODO(miek): more than one? Think TSIG?
			}
		}
		filter(res.AnswerPacket, dnssec)
	}

	res.AnswerPacket.Id = r.Id
	w.WriteMsg(res.AnswerPacket)
	return 0, nil
}

// Name implements the Handler interface.
func (ipr *Ipref) Name() string { return "ipref" }
