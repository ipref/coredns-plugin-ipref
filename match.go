package ipref

import (
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
)

func (ipr *Ipref) match(state request.Request) bool {
	for _, f := range ipr.from {
		if plugin.Name(f).Matches(state.Name()) {
			return true
		}
	}

	if ipr.isAllowedDomain(state.Name()) {
		return true

	}

	return false
}

func (ipr *Ipref) isAllowedDomain(name string) bool {
	for _, except := range ipr.except {
		if plugin.Name(except).Matches(name) {
			return false
		}
	}
	return true
}
