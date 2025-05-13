package ipref

import (
	"fmt"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	"net"
	"strings"
)

func init() {
	caddy.RegisterPlugin("ipref", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	ipr, err := iprefParse(c)
	if err != nil {
		return plugin.Error("ipref", err)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		ipr.Next = next
		return ipr
	})

	c.OnStartup(func() error {
		once.Do(func() {
			m := dnsserver.GetConfig(c).Handler("prometheus")
			if m == nil {
				return
			}
			if x, ok := m.(*metrics.Metrics); ok {
				x.MustRegister(RequestDuration)
				x.MustRegister(RcodeCount)
			}
		})
		return nil
	})
	c.OnShutdown(ipr.Stop)

	return nil
}

func iprefParse(c *caddy.Controller) (*Ipref, error) {
	ipr := &Ipref{
		m: &MapperClient{},
		ea_ipver: 4,
		gw_ipver: 4,
		mapper_socket: "/run/ipref/mapper.sock",
	}

	i := 0
	for c.Next() {
		// Return an error if ipref block specified more than once
		if i > 0 {
			return nil, plugin.ErrOnce
		}
		i++

		ipr.from = c.RemainingArgs()
		if len(ipr.from) == 0 {
			ipr.from = make([]string, len(c.ServerBlockKeys))
			copy(ipr.from, c.ServerBlockKeys)
		}
		for i, str := range ipr.from {
			ipr.from[i] = plugin.Host(str).NormalizeExact()[0]
		}

		for c.NextBlock() {
			name := c.Val()
			switch name {
			case "except":
				except := c.RemainingArgs()
				if len(except) == 0 {
					return nil, c.ArgErr()
				}
				for i := 0; i < len(except); i++ {
					except[i] = plugin.Host(except[i]).NormalizeExact()[0]
				}
				ipr.except = except

			case "upstream":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				ipr.upstream = strings.TrimSpace(args[0])
				if !addrHasPort(ipr.upstream) {
					ipr.upstream += ":53"
				}

			case "ea-ipver", "gw-ipver":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				var ipver int
				switch args[0] {
				case "4":
					ipver = 4
				case "6":
					ipver = 6
				default:
					return nil, c.ArgErr()
				}
				if name == "ea-ipver" {
					ipr.ea_ipver = ipver
				} else {
					ipr.gw_ipver = ipver
				}

			case "mapper":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				ipr.mapper_socket = args[0]

			default:
				return nil, c.ArgErr()
			}
		}
	}

	if ipr.upstream == "" {
		return nil, fmt.Errorf("missing upstream")
	}

	ipr.m.init()

	return ipr, nil
}

func addrHasPort(addr string) bool {
	_, _, err := net.SplitHostPort(addr)
	return err == nil
}
