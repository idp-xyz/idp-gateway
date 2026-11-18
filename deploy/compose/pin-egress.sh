#!/bin/sh
# Limit the new connections that leave a gateway's network namespace to the addresses its
# configuration names. Everything else is refused, IPv6 included.
#
#   once     resolve what is not pinned yet, install the rules, exit. compose.yml runs this before
#            the gateway starts, on every `docker compose up -d`.
#   watch    the same every INTERVAL seconds, so a host a later publication adds becomes reachable
#            and a host it removes stops being reachable. A pass that fails does not end it: the
#            rules in force stay in force, it says why, once, and tries again at the next interval,
#            and it says when passes work again. It ends only when the namespace loses its address.
#   forget   drop every pin, the ones not allowed now too, and resolve again. For a backend whose
#            address really has changed.
#
# What is allowed: answers to connections already open; the resolvers; LOOP_ALLOW; and, per
# `host: name:port` that CONFIG names as it is now, the IPv4 addresses the name resolved to the
# first time it resolved, on that port. A literal IPv4 address is allowed as written.
#
# A name is resolved once. What it resolves to later is not added: a gateway follows a name to
# wherever it points (tests/integration/egressnet), and that is what this is here to stop.
# A name that has not resolved yet is tried again on the next run.
#
# A `name:port` that CONFIG stops naming is not allowed from the next run on: new connections to its
# addresses on that port are refused, and the ones already open are left alone. Its addresses are
# still remembered. When a later CONFIG names it again (a rollback after a failed publication does),
# it is allowed on the addresses it had and not on whatever the name resolves to by then, so the
# name is still resolved once. Only forget drops what is remembered. The run that stops or resumes
# allowing a `name:port` says so, once, on stderr.
#
# A run that finds no CONFIG file changes nothing about what is allowed: it installs the fixed rules
# and leaves every pin as it was, allowed or not. Only a file that is there and can be read takes a
# pin out of what is allowed. A file or directory that cannot be read fails the run and changes
# nothing: once and forget exit non-zero at once, watch says so and tries again. (forget drops
# everything, so with no file it leaves nothing allowed.)
#
# The pins are kept in the rules themselves, as comments, so they live exactly as long as the
# namespace does and are the same whichever container runs this. There are two chains. IDP_EGRESS
# holds the rules in force, with the pins that are allowed. IDP_EGRESS_KEPT holds every pin, allowed
# or not, and nothing jumps to it: it is only there to remember.
#
# Both chains are replaced in one transaction: there is no moment at which IDP_EGRESS is empty.
# OUTPUT jumps to it; the jump is added after the chain is filled.
#
# CONFIG      the agentgateway file. Not there: what is allowed stays as it is.
# LOOP_ALLOW  comma-separated address:port on loopback that may be opened: the front proxy's
#             connection to the gateway. Loopback is otherwise refused like any other address.
# INTERVAL    seconds between two runs in watch mode.
set -eu

CONFIG=${CONFIG:-/work/config/config.yaml}
LOOP_ALLOW=${LOOP_ALLOW-127.0.0.1:8081}
INTERVAL=${INTERVAL:-2}
WORK=${WORK:-/tmp}
CHAIN=IDP_EGRESS
KEPT=${CHAIN}_KEPT
MODE=${1:-once}
FORGET=
ABSENT=

say() {
    echo "pin-egress: $*" >&2
}

is_ipv4() {
    printf '%s\n' "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
}

# Every `host: name:port` of the configuration, one name:port per line. Block style only: a host
# written some other way is not found, and what is not found is not allowed. With no file there is
# nothing to list, and ABSENT says so: that is not the same as a file that names nothing.
#
# Whether a file can be read is found out by reading it. `[ -r ]` is no use here: busybox answers yes
# to it for root whatever the modes are, and this runs as root with no capability that overrides them.
# The file is read into a file of its own first, because the status of a pipeline is its last
# command's: a read that failed at the front of one would pass for a configuration that names nothing.
hosts() {
    directory=$(dirname "$CONFIG")
    if [ ! -e "$directory/." ]; then
        say "cannot look into $directory"
        return 1
    fi
    if [ ! -e "$CONFIG" ]; then
        ABSENT=yes
        return 0
    fi
    if [ ! -f "$CONFIG" ]; then
        say "$CONFIG is not a file"
        return 1
    fi
    if ! sed -n 's/^[[:space:]-]*host:[[:space:]]*\([^[:space:]#]*\).*/\1/p' "$CONFIG" > "$WORK/hostlines"; then
        if [ ! -e "$CONFIG" ]; then   # taken away since the look above
            ABSENT=yes
            return 0
        fi
        say "cannot read $CONFIG"
        return 1
    fi
    tr -d "\"'" < "$WORK/hostlines" | sort -u |
        while IFS= read -r spec; do
            if printf '%s\n' "$spec" | grep -Eq '^[A-Za-z0-9._-]+:[0-9]{1,5}$'; then
                printf '%s\n' "$spec"
            else
                say "not a name:port, left out: $spec"
            fi
        done
}

# The IPv4 addresses a name resolves to now, one per line; nothing when it does not resolve.
resolve() {
    if is_ipv4 "$1"; then
        printf '%s\n' "$1"
        return 0
    fi
    nslookup "$1" 2>/dev/null | awk '
        $1 == "Name:" { seen = 1; next }
        seen && /^Address/ { for (i = 2; i <= NF; i++) if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print $i }
    ' | sort -u || true
}

# The pins chain $1 holds now, as "name:port address" lines. None in forget mode: that is how it
# drops them.
pins_in() {
    [ -z "$FORGET" ] || return 0
    iptables -S "$1" 2>/dev/null |
        sed -n 's/.* -d \([0-9.]*\)\/32 .*--comment "\{0,1\}pin:\([^" ]*\)"\{0,1\}.*/\2 \1/p' || true
}

# Is $1 the first word of a line of file $2?
listed() {
    awk -v key="$1" '$1 == key { found = 1 } END { exit !found }' "$2"
}

# The resolvers of this namespace. Docker answers on a loopback address and rewrites the port of a
# query before the filter sees it, so those are matched by where the query was first sent. Names it
# does not know itself it asks the servers on the ExtServers line, from inside this namespace.
nameservers() {
    sed -n 's/^nameserver[[:space:]]*\([0-9.]*\)[[:space:]]*$/\1/p' /etc/resolv.conf
}

upstream_resolvers() {
    sed -n 's/^# ExtServers: \[\(.*\)\]$/\1/p' /etc/resolv.conf | tr ' ,' '\n\n' | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || true
}

attached() {
    ip -o -4 addr show scope global 2>/dev/null | grep -q .
}

# Two containers run this in one namespace (the step before the gateway, and the watcher), and they
# share nothing but the namespace. Creating a chain either succeeds or fails because it is there:
# that is the lock. One left behind by a run that was killed is taken over after ten seconds.
HELD=
lock() {
    waited=0
    until iptables -N "${CHAIN}_BUSY" 2>/dev/null; do
        waited=$((waited + 1))
        if [ "$waited" -ge 50 ]; then
            say "taking over a lock that was left behind"
            break
        fi
        sleep 0.2
    done
    HELD=yes
}

unlock() {
    [ -n "$HELD" ] || return 0
    iptables -X "${CHAIN}_BUSY" 2>/dev/null || true
    HELD=
}

trap unlock EXIT
trap 'exit 143' TERM INT HUP

apply() {
    lock
    write_rules
    unlock
}

write_rules() {
    wanted=$WORK/wanted pins=$WORK/pins rules=$WORK/rules
    was=$WORK/was remembered=$WORK/remembered allowed=$WORK/allowed
    ABSENT=
    hosts > "$wanted"
    # pins: every pin remembered, allowed or not. was: the name:port the chain in force allows now.
    pins_in "$KEPT" > "$pins"
    pins_in "$CHAIN" | awk '{ print $1 }' | sort -u > "$was"
    awk '{ print $1 }' "$pins" | sort -u > "$remembered"
    while IFS= read -r spec; do
        if listed "$spec" "$pins"; then
            continue
        fi
        for address in $(resolve "${spec%:*}"); do
            printf '%s %s\n' "$spec" "$address" >> "$pins"
            echo "pinned $spec -> $address"
        done
    done < "$wanted"

    # Allowed from this run on: what CONFIG names now. With no CONFIG file, what was allowed.
    if [ -n "$ABSENT" ]; then
        cp "$was" "$allowed"
    else
        cp "$wanted" "$allowed"
    fi
    while IFS= read -r spec; do
        listed "$spec" "$allowed" || say "no longer allowed, still remembered: $spec"
    done < "$was"
    while IFS= read -r spec; do
        if ! listed "$spec" "$was" && listed "$spec" "$remembered"; then
            say "allowed again, on the addresses it had: $spec"
        fi
    done < "$allowed"

    {
        echo '*filter'
        echo ":$CHAIN - [0:0]"
        echo ":$KEPT - [0:0]"
        echo "-A $CHAIN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
        for server in $(nameservers); do
            echo "-A $CHAIN -p udp -m conntrack --ctorigdst $server --ctorigdstport 53 -j ACCEPT"
            echo "-A $CHAIN -p tcp -m conntrack --ctorigdst $server --ctorigdstport 53 -j ACCEPT"
        done
        for server in $(upstream_resolvers); do
            echo "-A $CHAIN -d $server/32 -p udp -m udp --dport 53 -j ACCEPT"
            echo "-A $CHAIN -d $server/32 -p tcp -m tcp --dport 53 -j ACCEPT"
        done
        for item in $(printf '%s' "$LOOP_ALLOW" | tr ',' ' '); do
            echo "-A $CHAIN -d ${item%:*}/32 -p tcp -m tcp --dport ${item##*:} -j ACCEPT"
        done
        while read -r spec address; do
            listed "$spec" "$allowed" || continue
            echo "-A $CHAIN -d $address/32 -p tcp -m tcp --dport ${spec##*:} -m comment --comment \"pin:$spec\" -j ACCEPT"
        done < "$pins"
        # Not a reset and not "port unreachable": the gateway and anyone reading its log can tell
        # a connection refused here (no route to host) from one the other side refused.
        echo "-A $CHAIN -j REJECT --reject-with icmp-admin-prohibited"
        # The memory. RETURN, so that a jump to it by mistake would still allow nothing.
        while read -r spec address; do
            echo "-A $KEPT -d $address/32 -p tcp -m tcp --dport ${spec##*:} -m comment --comment \"pin:$spec\" -j RETURN"
        done < "$pins"
        echo COMMIT
    } > "$rules"
    iptables-restore --noflush < "$rules"
    iptables -C OUTPUT -j "$CHAIN" 2>/dev/null || iptables -I OUTPUT 1 -j "$CHAIN"

    # No pin is an IPv6 address, so no new IPv6 connection is allowed. Where the kernel has no
    # IPv6 there is nothing to refuse; where it has, failing to install this stops the script.
    # (The file is in /proc: its size is always 0, so it is read, not measured.)
    if [ -n "$(cat /proc/net/if_inet6 2>/dev/null)" ]; then
        {
            echo '*filter'
            echo ":$CHAIN - [0:0]"
            echo "-A $CHAIN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
            echo "-A $CHAIN -j REJECT --reject-with icmp6-adm-prohibited"
            echo COMMIT
        } | ip6tables-restore --noflush
        ip6tables -C OUTPUT -j "$CHAIN" 2>/dev/null || ip6tables -I OUTPUT 1 -j "$CHAIN"
    fi
}

# One pass of watch mode. A pass that fails does not end the watcher (nothing restarts it, and it is
# what allows a backend a later publication adds): the rules are as the failed pass found them, the
# lock is let go, the next interval tries again. What a pass said on stderr is held back: the first time
# one fails it is said, with a line of our own; it is not said again while it fails the same way, and
# one line says when passes work again.
#
# The body of the pass has to stop at its first failing command, as it does in once and forget. In
# POSIX sh errexit is ignored inside whatever runs as the condition of `if` or `while`, on the left
# of `||` or `&&`, or after `!`, a subshell and a function included. So the pass is not called that
# way: `apply` runs in a subshell of its own that sets `set -e` itself, and that subshell is a command
# on a line of its own, with errexit off around it only so that its status can be read. The subshell
# sets its own traps too: it does not take over those of this shell, and the lock must be let go
# however it ends. (A guard in tests/contracts looks for the forms that lose errexit; EG-08 in
# tests/integration/egressnet shows that a pass whose `hosts` fails installs nothing.)
FAILING=0
LAST=
one_pass() {
    set +e
    (
        set -e
        trap unlock EXIT
        trap 'exit 143' TERM INT HUP
        apply
    ) 2> "$WORK/said"
    status=$?
    set -e
    said=$(cat "$WORK/said" 2>/dev/null || true)
    if [ "$status" -eq 0 ]; then
        if [ -n "$said" ]; then
            printf '%s\n' "$said" >&2
        fi
        if [ "$FAILING" -gt 0 ]; then
            say "watch: passes work again, after $FAILING that failed"
            FAILING=0
            LAST=
        fi
        return 0
    fi
    FAILING=$((FAILING + 1))
    if [ "$FAILING" -eq 1 ] || [ "$said" != "$LAST" ]; then
        if [ -n "$said" ]; then
            printf '%s\n' "$said" >&2
        fi
        if [ "$FAILING" -eq 1 ]; then
            say "watch: a pass failed (exit $status); the rules in force stay in force and it is tried again every ${INTERVAL}s. This is not said again unless the failure changes; one line says when passes work again"
        else
            say "watch: passes are still failing, now for another reason (see above)"
        fi
    fi
    LAST=$said
    return 0
}

if ! attached; then
    say "this network namespace has no address of its own: started beside a holder that is gone"
    exit 1
fi

case $MODE in
    once)
        apply
        ;;
    forget)
        FORGET=yes
        apply
        ;;
    watch)
        while attached; do
            one_pass
            sleep "$INTERVAL"
        done
        say "the network namespace lost its address; the next start joins the one that replaced it"
        exit 1
        ;;
    *)
        say "once, watch or forget"
        exit 2
        ;;
esac
