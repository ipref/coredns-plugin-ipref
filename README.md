# ipref

## Name

*ipref* - perform recursive queries that can resolve IPREF addresses

## Description

Via *ipref* you can perform recursive queries that resolve IPREF addresses in addition to
standard IPv4 and IPv6 addresses. Ipref is based on unboud plugin which uses libunbound
library. Unbound uses DNSSEC by default when resolving *and* it returns those records
(DNSKEY, RRSIG, NSEC and NSEC3) back to the clients. The *ipref* plugin will remove those
records when a client didn't ask for it. The internal (RR) answer cache of Unbound is
disabled, so you may want to use the *cache* plugin.

Libunbound can be configured via (a subset of) options, currently the following are set, by default:

* `msg-cache-size`, set to 0
* `rrset-cache-size`, set to 0

This plugin can only be used once per Server Block.

## Syntax

~~~
ipref [FROM]
~~~

* **FROM** is the base domain to match for the request to be resolved. If not specified the zones
  from the server block are used.

More features utilized with an expanded syntax:

~~~
ipref [FROM] {
    except IGNORED_NAMES...
    option NAME VALUE
}
~~~

* **FROM** as above.
* **IGNORED_NAMES** in `except` is a space-separated list of domains to exclude from resolving.
* `option` allows setting *some* unbound options (see unbound.conf(5)), this can be specified multiple
  times.

## Metrics

If monitoring is enabled (via the *prometheus* directive) then the following metric is exported:

* `coredns_ipref_request_duration_seconds{server}` - duration per query.
* `coredns_ipref_response_rcode_count_total{server, rcode}` - count of RCODEs.

The `server` label indicates which server handled the request, see the *metrics* plugin for details.

## Examples

Resolve queries for all domains:
~~~ corefile
. {
    ipref
}
~~~

Resolve all queries within example.org.

~~~ corefile
. {
    ipref example.org
}
~~~

or

~~~ corefile
example.org {
    ipref
}
~~~

Resolve everything except queries for example.org (or below):

~~~ corefile
. {
    ipref {
        except example.org
    }
}
~~~

Enable [DNS Query Name Minimisation](https://tools.ietf.org/html/rfc7816) by setting the option:

~~~ corefile
. {
    ipref {
        option qname-minimisation yes
    }
}
~~~

## Bugs

IPREF needs new DNS resource record type. The plan is to register AA records with IANA.
For now, as a workaround to allow development, the unavailable AA records are emulated
by embedding them in TXT records. This is invisible to host performing name resolution.

The *ipref* plugin depends on libunbound(3) which is C library, to compile this you have
a dependency on C and cgo. You can't compile CoreDNS completely static. For compilation you
also need the libunbound source code installed (`libunbound-dev` on Debian).

DNSSEC *validation* is not supported (yet). There is also no (documented) way of configurating
a trust anchor.

## See Also

See <https://github.com/coredns/unbound> for information on the unboud plugin.
See <https://unbound.net> for information on Unbound and unbound.conf(5). See
<https://github.com/miekg/unbound> for the (cgo) Go wrapper for libunbound.
