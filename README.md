# ipref

## Name

*ipref* - recursively translate IPREF AA records into A/AAAA records by communicating with the IPREF
mapper

## Description

Each incoming A/AAAA DNS query that reaches the *ipref* plugin will result in a recursive query to
the configured upstream server for an IPREF AA record (encoded in TXT records beginning with "AA").
The *ipref* plugin will then communicate with the [gateway](https://github.com/ipref/gw) mapper over
a Unix domain socket to get the encoded address associated with the IPREF address returned by the
upstream server, and then the encoded address is returned in an A/AAAA response.

If the query cannot be served by translating an IPREF address, then the next plugin in the chain is
executed (even if the upstream has an A/AAAA record). If you'd like to combine IPREF translation
with normal DNS resolution, see the [forward](https://coredns.io/plugins/forward/) plugin (example
below).

This plugin can only be used once per Server Block.

This code includes technology covered by patent US 10,749,840 B2.

## Syntax

~~~
ipref [FROM...] {
    except IGNORED_NAMES...
    upstream ADDR
    ea-ipver 4|6
    gw-ipver 4|6
    mapper PATH
}
~~~

* **FROM** is the base domains to match for the request to be resolved. If not specified the zones
  from the server block are used.
* **IGNORED_NAMES** in `except` is a space-separated list of domains to exclude from resolving.
* `upstream` specifies the address of the upstream DNS server (eg. `8.8.8.8`).
* `ea-ipver` and `gw-ipver` specify the IP versions (IPv4 or IPv6) to use for the encoded address
  network (local network) and IPREF gateway tunnel, respectively. The default for both is IPv4.
* `mapper` specifies the path to the Unix domain socket for communication with the gateway - the
  default is `/run/ipref/mapper.sock`.

## Metrics

If monitoring is enabled (via the *prometheus* directive) then the following metric is exported:

* `coredns_ipref_request_duration_seconds{server}` - duration per query.
* `coredns_ipref_response_rcode_count_total{server, rcode}` - count of RCODEs.

The `server` label indicates which server handled the request, see the *metrics* plugin for details.

## Example

Translate IPREF AA records for everything under `example.com` (except everything under
`www.example.com`) using `8.8.8.8` as the upstream source for AA records. If no valid AA records are
found, or if the domain is excluded, then the request is forwarded to `8.8.8.8`. Note that this
requires `ipref` to be above `forward` in `plugin.cfg`.

~~~ corefile
. {
    ipref example.com {
        except www.example.com
        upstream 8.8.8.8
        ea-ipver 4
        gw-ipver 4
    }
    forward . 8.8.8.8
}
~~~

## Compiling into CoreDNS

To compile this with CoreDNS you can follow the normal procedure for external plugins.

You may need to add these dependencies to CoreDNS's `go.mod`:

~~~
require (
	github.com/ipref/common v1.2.0
	github.com/ipref/ref v0.0.0-20230130062235-2e91b82300b7
)
~~~

## Bugs

IPREF needs new DNS resource record type. The plan is to register AA records with IANA.
For now, as a workaround to allow development, the unavailable AA records are emulated
by embedding them in TXT records. This is invisible to hosts requesting name resolution.

## See Also

See <https://github.com/ipref/dns> for information on IPREF addressing.

This plugin was originally based on the [unbound](https://github.com/coredns/unbound) plugin, but it
has since been rewritten to perform forwarding instead.
