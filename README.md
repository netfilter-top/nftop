## Introduction
`nftop` is a top-like utility to display bandwidth utilization, connection state, source/destination addresses/hostnames, protocol, port, connection age and in/out interface of netfilter connection-tracking entires.

This utility is only viable when utilizing netfilter connection tracking (i.e. SNAT/DNAT/MASQ, or statfull firewall rules) with netfilter connection accounting enabled.

I cobbled this together when faced with the challenge of running a network on 4 LTE modems, which disconnect often, making utilities such as `iftop` not viable (`iftop` tracks an interface, if that interface is transient it would have to be invoked again).

The code is shitty, but seems stable and memory leak-free.

This utility was inspired by tools like `iftop` and `pftop` (on BSD). This being for netfilter connections has the added benifit of providing bandwidth utilization for all connections and all interfaces tracked by netfilter.

The support for ncurses is incomplete, but should be usable, but it doesn't buy much. The default build is without ncurses entirely. I started adding support for it because I would like for `nftop` to be more interactive and do things like close/reset connections. But perhaps `nftop` will remain a monitoring-only utility. Who knows.

## Demo
[![asciicast](https://asciinema.org/a/VJtVhDe4NT4y8F3uAutmEn7Yw.svg)](https://asciinema.org/a/VJtVhDe4NT4y8F3uAutmEn7Yw)

## Runtime requirements
`nftop` is only useful if netfilter connection tracking and accounting is enabled. Furthermore, the age/timestamp field is only available if `net.netfilter.nf_conntrack_timestamp` is enabled.

example setup for usage:
  ```
  sysctl -w net.netfilter.nf_conntrack_acct=1
  sysctl -w net.netfilter.nf_conntrack_timestamp=1
  ```

  If not already using stateful firewall rules, the following iptables rules will enable tracking for all ipv4 and ipv6 connections. This sets up a new chain that never gets used, but enables the `state` module. If you are using DNAT, SNAT or stateful firewall rules, you don't need this chain.
  ```
  iptables -t filter -N TRACKING
  iptables -t filter -A TRACKING -m state --state NEW,RELATED,ESTABLISHED,INVALID -j RETURN

  ip6tables -t filter -N TRACKING
  ip6tables -t filter -A TRACKING -m state --state NEW,RELATED,ESTABLISHED,INVALID -j RETURN
  ```

  If you are doing policy routing via marks, the mark needs to be exported to the connection tracking mark (`CONNMARK`). The following example exports the skb mark to the connection tracking mark, but this will need to be after setting the mark. Just an example.
  ```
  iptables -t mangle -A PREROUTING -j CONNMARK --save-mark
  ```

## Usage
```
nftop: Display connection information from netfilter conntrack entries (including at-the-time throughput values for transmit, receive and sum)
Usage:
nftop [-46dbnNPrRS] [-a age_format] [-i in interface] [-o out interface] [-s sort column] [-t threshold] [-u update interval]  [-w]
  -4					output only IPv4 connections
  -6					output only IPv6 connections
  -d|--dev				output device table instead of connections
  -b|--bytes			output bytes insted of default bits
  -B|--bps				output the connection/interface only in bits-per-second, without scaling to Kbps, Mpbs, etc.
  -c|--continuous		output continously without display header or performing screen refresh
  -I|--id				output connection tracking ID
  -L|--loopback			include connections on loopback interfaces (IFF_LOOPBACK)
  -n|--numeric-local	numeric local IP address
  -N|--numeric-remote	numeric remote IP address
  -M|--machine			output continuously without header and do not scale the unit (bps/Bps only) (-c and -B)
  -P|--numeric-port		numeric port
  -r|--redact-local		obfuscate the local connection address
  -R|--redact-remote	obfuscate the remote connection address
  -S|--si				output Standards International nomenclature (Ki, Mi, Gi, ...)
  -a|--age  0-2			format of age column 0: do not display, 1: seconds, 2: DD HH MM SS format (default is do not display)
							(only availble if "net.netfilter.nf_conntrack_timestamp" kernel option is enabled)
  -t|--threshold  bits	minimum SUM value to display (in bits)
  -u|--update  seconds	update interval in seconds
  -i|--in    interface	interface name to filter as input interface
  -o|--out   interface	interface name to filter as output interface
  -s|--sort  [+]column	column to sort by -- one of [id, in, out, sport, dport, rx, tx, sum]
							the default is DESCENDING order; use +column to sort in ASCENDING order
  -v|--version			version
  -V|--verbose			Enable the TCP state field
  -w|--wide		output report in wide format (single row for both SRC and DST)

Examples:
  nftop -o wwan0	- only output connections that egress interface "wwan0"
  nftop -t 1000000	- only output connections that are at least 1Mbps (sum)
  nftop -i vlan+	- only output connections that match ingress interface "vlan*"
  nftop -s +id		- sort output by ID column in ASCENDING order

Notes:
  The reporting of the in/out interface is derived via a route lookup of the connection source/destination address(es) and marks,
  This could result in false reporting in certain cases (e.g.: not using `CONNMARK`, source/dest port policy routing, multi-path, traffic queues, etc.)

Requirements:
  netfilter connection tracking
  netfilter connection accounting (net.netfilter.nf_conntrack_acct)
    - sysctl net.netfilter.nf_conntrack_acct=1
  root or cap_net_admin+eip permissions
```

## Build dependencies
  * libmnl-dev
  * libnetfilter-conntrack-dev
  * libncurses-dev (if ncurses enabled)
