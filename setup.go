package ipref

import (
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
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
	ipr := New()

	i := 0
	for c.Next() {
		// Return an error if unbound block specified more than once
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
			var args []string
			var err error

			switch c.Val() {
			case "except":

				except := c.RemainingArgs()
				if len(except) == 0 {
					return nil, c.ArgErr()
				}
				for i := 0; i < len(except); i++ {
					except[i] = plugin.Host(except[i]).NormalizeExact()[0]
				}
				ipr.except = except

			case "option":
				args = c.RemainingArgs()
				if len(args) != 2 {
					return nil, c.ArgErr()
				}
				if err = ipr.setOption(args[0], args[1]); err != nil {
					return nil, err
				}
			case "config":
				args = c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				if err = ipr.config(args[0]); err != nil {
					return nil, err
				}

			case "mapper":

				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				if !strings.HasPrefix(args[0], "unix://") {
					return nil, c.Err("invalid protocol type")
				}

				if strings.HasPrefix(args[0], "unix:///") {
					ipr.m.sockname = args[0][7:]
				} else {
					ipr.m.sockname = "/" + args[0][7:]
				}

			default:
				return nil, c.ArgErr()
			}
		}
	}
	return ipr, nil
}
