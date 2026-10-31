#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A large blocklist is looked up through an index instead of rule by rule.
# Through the proxy, on every available event loop, check that its answers
# are still the first matching rule in file order: an earlier ACCEPT beats a
# later REJECT for the same target, a network and a domain deep in the list
# are refused, a rule that is not indexable still applies in its place, and
# a reload that rewrites the list takes effect.

. "$(dirname "$0")/lib.sh"
require python3

hp="$(pick_port)"
start_httpd "$hp" "$WORK" "1.1"

# write_acl <file> <verdict for 127.0.0.1>: about 10000 indexable rules,
# with the entries for loopback targets spread through them.
write_acl() {
	python3 - "$1" "$2" <<-'PY'
	import sys
	path, v1 = sys.argv[1], sys.argv[2]
	r = ['-P OUTPUT ACCEPT']
	for i in range(3000):
	    r.append('-A OUTPUT -d 10.%d.%d.%d -j REJECT' % (i >> 16, (i >> 8) & 255, i & 255))
	r.append('-A OUTPUT -m domain --domain LocalHost -j REJECT')
	r.append('-A OUTPUT -d 127.0.0.1 -j %s' % v1)
	for i in range(3000):
	    r.append('-A OUTPUT -m domain --domain h%d.blocked.example -j REJECT' % i)
	r.append('-A OUTPUT -d 127.0.0.0/8 -j REJECT')
	for i in range(3000):
	    r.append('-A OUTPUT -d 172.%d.%d.0/24 -j REJECT' % (16 + (i >> 8), i & 255))
	# Not indexable (two criteria): tested in its place, after the run.
	r.append('-A OUTPUT -d 192.0.2.0/24 --dports 1-65535 -j REJECT')
	for i in range(1000):
	    r.append('-A OUTPUT -d 2001:db8:%x::/48 -j REJECT' % i)
	open(path + '.new', 'w').write('\n'.join(r) + '\n')
	PY
	mv -f "$1.new" "$1"
}

probe() {			# $1=proxy_port $2=atyp $3=dst
	python3 "$SERVERS_DIR/socks5_probe.py" --host 127.0.0.1 --atyp "$2" \
		--dst "$3" "$1" "$hp"
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	write_acl "$WORK/big.acl" ACCEPT
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--acl-file="$WORK/big.acl"

	rep="$(probe "$pp" ipv4 127.0.0.1)"
	[ "$rep" = "REP=0x00" ] || fail "[$loop] 127.0.0.1 not accepted by the earlier rule ($rep)"
	rep="$(probe "$pp" ipv4 127.0.0.2)"
	[ "$rep" = "REP=0x02" ] || fail "[$loop] 127.0.0.2 not refused by 127.0.0.0/8 ($rep)"
	rep="$(probe "$pp" domain localhost)"
	[ "$rep" = "REP=0x02" ] || fail "[$loop] localhost not refused by its -m domain rule ($rep)"
	rep="$(probe "$pp" ipv4 192.0.2.1)"
	[ "$rep" = "REP=0x02" ] || fail "[$loop] the rule after the run did not apply ($rep)"

	# The new list refuses 127.0.0.1 too.
	write_acl "$WORK/big.acl" REJECT
	for _ in $(seq 1 100); do
		grep -q "Reloaded ACL file" "$WORK/gwp.$pp.log" && break
		sleep 0.1
	done
	grep -q "Reloaded ACL file" "$WORK/gwp.$pp.log" \
		|| fail "[$loop] ACL was not reloaded"
	rep="$(probe "$pp" ipv4 127.0.0.1)"
	[ "$rep" = "REP=0x02" ] || fail "[$loop] reloaded list did not refuse 127.0.0.1 ($rep)"
	kill "$GWP_PID" 2>/dev/null
done

pass
