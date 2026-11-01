#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# --auth-file and --acl-file are reloaded however the file the path leads to
# was changed, not only through the configured name in its directory: behind
# a symlink, by a Kubernetes-style "..data" swap, by swapping the parent
# directory (and by editing the file in the new directory afterwards), and by
# unlink and link. Exercised on every available event loop.
#
# Most of these changes take the check several seconds to apply, so all the
# proxies are started first and then wait for their changes at the same time,
# which keeps the test well within the time limit t/run-one.sh gives it.

. "$(dirname "$0")/lib.sh"
require curl

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 1000
start_httpd "$hp" "$WORK" "1.1"

# fetch <proxy-port> <user> <pass>: succeed iff the proxy let the request
# through to the origin.
fetch()
{
	curl -s --max-time 30 --proxy "socks5h://$2:$3@127.0.0.1:$1" \
		"http://127.0.0.1:$hp/payload.bin" -o /dev/null
}

# wait_fetch <want:0|1> <proxy-port> <user> <pass>: poll until fetch()
# succeeds (want=1) or fails (want=0).
wait_fetch()
{
	local i ok

	for i in $(seq 1 200); do
		ok=0
		fetch "$2" "$3" "$4" && ok=1
		[ "$ok" = "$1" ] && return 0
		sleep 0.1
	done
	return 1
}

# Each layout_* sets up $d with alice as the credential in force, sets
# $path to the path to configure, and has an update_* that makes bob the
# credential instead and revokes alice.

layout_target_inplace()
{
	mkdir "$d/real" "$d/cfg"
	echo alice:pw >"$d/real/auth"
	ln -s "$d/real/auth" "$d/cfg/auth"
	path="$d/cfg/auth"
}
update_target_inplace() { echo bob:pw >"$d/real/auth"; }

layout_target_rename() { layout_target_inplace; }
update_target_rename()
{
	echo bob:pw >"$d/real/auth.new"
	mv -f "$d/real/auth.new" "$d/real/auth"
}

layout_data_swap()
{
	mkdir "$d/vol" "$d/vol/..v1" "$d/vol/..v2"
	echo alice:pw >"$d/vol/..v1/auth"
	echo bob:pw >"$d/vol/..v2/auth"
	ln -s ..v1 "$d/vol/..data"
	ln -s ..data/auth "$d/vol/auth"
	path="$d/vol/auth"
}
update_data_swap()
{
	ln -s ..v2 "$d/vol/..tmp"
	mv -T "$d/vol/..tmp" "$d/vol/..data"
}

layout_dir_swap()
{
	mkdir "$d/cur" "$d/new"
	echo alice:pw >"$d/cur/auth"
	echo bob:pw >"$d/new/auth"
	path="$d/cur/auth"
}
update_dir_swap()
{
	mv "$d/cur" "$d/old"
	mv "$d/new" "$d/cur"
}

layout_unlink_link()
{
	mkdir "$d/other"
	echo alice:pw >"$d/auth"
	echo bob:pw >"$d/other/new"
	path="$d/auth"
}
update_unlink_link()
{
	rm -f "$d/auth"
	ln "$d/other/new" "$d/auth"
}

allow=$'-P INPUT ACCEPT\n-P OUTPUT ACCEPT\n'
deny="-A OUTPUT -d 127.0.0.1 --dports $hp -j REJECT"$'\n'"$allow"

names=()
acl_names=()
acl_ports=()
acl_dirs=()
ports=()
dirs=()
paths=()
pids=()

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	for how in target_inplace target_rename data_swap dir_swap unlink_link; do
		d="$WORK/$loop.$how"
		mkdir "$d"
		"layout_$how"
		pp="$(pick_port)"
		gwp_start "127.0.0.1:$pp" --as-socks5=1 --auth-file="$path" \
			--acl-allow-all --event-loop="$loop" --nr-workers=1
		fetch "$pp" alice pw || fail "[$loop/$how] initial credentials rejected"
		fetch "$pp" bob pw && fail "[$loop/$how] bob accepted too early"
		names+=("$loop/$how")
		ports+=("$pp")
		dirs+=("$d")
		paths+=("$path")
		pids+=("$GWP_PID")
	done

	# The ACL takes the same path through the reload thread.
	d="$WORK/$loop.acl"
	mkdir "$d" "$d/real" "$d/cfg"
	printf '%s' "$allow" >"$d/real/acl"
	ln -s "$d/real/acl" "$d/cfg/acl"
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --acl-file="$d/cfg/acl" \
		--event-loop="$loop" --nr-workers=1
	fetch "$pp" x x || fail "[$loop/acl] the origin is not allowed at first"
	acl_names+=("$loop/acl")
	acl_ports+=("$pp")
	acl_dirs+=("$d")
	pids+=("$GWP_PID")
done

# Every change at once, then every outcome: the wait for one covers the others.
for i in "${!names[@]}"; do
	d="${dirs[i]}"
	"update_${names[i]#*/}"
done
for d in "${acl_dirs[@]}"; do
	printf '%s' "$deny" >"$d/real/acl.new"
	mv -f "$d/real/acl.new" "$d/real/acl"
done

for i in "${!names[@]}"; do
	wait_fetch 0 "${ports[i]}" alice pw \
		|| fail "[${names[i]}] the revoked credentials still work"
	wait_fetch 1 "${ports[i]}" bob pw \
		|| fail "[${names[i]}] the new credentials are refused"
done
for i in "${!acl_names[@]}"; do
	wait_fetch 0 "${acl_ports[i]}" x x \
		|| fail "[${acl_names[i]}] the new rules did not apply"
done

# The watch must not be stuck on the old directory.
for i in "${!names[@]}"; do
	[ "${names[i]#*/}" = dir_swap ] && echo carol:pw >"${paths[i]}"
done
for i in "${!names[@]}"; do
	[ "${names[i]#*/}" = dir_swap ] || continue
	wait_fetch 1 "${ports[i]}" carol pw \
		|| fail "[${names[i]}] a later edit was not loaded"
done

kill "${pids[@]}" 2>/dev/null

pass
