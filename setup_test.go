package ipref

import (
	"testing"

	"github.com/mholt/caddy"
)

func TestSetup(t *testing.T) {
	tests := []struct {
		input     string
		shouldErr bool
	}{
		{`ipref`, false},
		{`ipref .`, false},
		{`ipref a b`, false},
	}

	for i, test := range tests {
		c := caddy.NewTestController("dns", test.input)
		_, err := iprefParse(c)

		if test.shouldErr && err == nil {
			t.Errorf("Test %d: Expected error but found none for input %s", i, test.input)
		}

		if err != nil {
			if !test.shouldErr {
				t.Errorf("Test %d: Expected no error but found one for input %s. Error was: %v", i, test.input, err)
			}
		}
	}
}

func TestSetupExtended(t *testing.T) {
	tests := []struct {
		input     string
		shouldErr bool
	}{
		{`ipref {
			option msg-cache-size 0
			option msg-cache-size 0
		}`, false},
		{`ipref {
			option msg-cache-size 0
			except example.org example.net
		}`, false},

		{`ipref {
			option bla yes
		}`, true},
		{`ipref {
			optoin qname-minimisation yes
		}`, true},
	}

	for i, test := range tests {
		c := caddy.NewTestController("dns", test.input)
		_, err := iprefParse(c)

		if test.shouldErr && err == nil {
			t.Errorf("Test %d: Expected error but found none for input %s", i, test.input)
		}

		if err != nil {
			if !test.shouldErr {
				t.Errorf("Test %d: Expected no error but found one for input %s. Error was: %v", i, test.input, err)
			}
		}
	}
}
