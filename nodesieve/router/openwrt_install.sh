#!/bin/sh
# Installs nodesieve on an OpenWrt router, or removes it. `python -m nodesieve
# install-router` uploads the code to NS_ARCHIVE, then streams this script to `sh -s`
# with these set:
#   NS_MODE      install or remove
#   NS_EVERY     hours between scheduled scans, 0 for none
#   NS_WEB       the directory the router's web server serves the feed from
#   NS_PACKAGES  the packages nodesieve needs
#   NS_SETTINGS  the settings for a router that has none yet, as one line of JSON
# It reports back in lines starting NS_NOTE, NS_INFO (key=value) and NS_ERROR, and
# prints NS_OK only when everything is done. The whole body is one function, so the
# shell has read all of it before anything runs.
set -eu
umask 077
ns_main() {
DIR=/opt/nodesieve
TAG='# nodesieve-scan'
CRONTAB=/etc/crontabs/root
fail() { printf 'NS_ERROR: %s\n' "$1" >&2; exit 1; }
note() { printf 'NS_NOTE: %s\n' "$1"; }
info() { printf 'NS_INFO: %s=%s\n' "$1" "$2"; }
: "${NS_MODE:?}" "${NS_EVERY:?}" "${NS_WEB:?}" "${NS_ARCHIVE:?}" "${NS_PACKAGES:?}" "${NS_SETTINGS:?}"
trap 'rm -f "$NS_ARCHIVE"' EXIT
case "$NS_WEB" in
    /*/nodesieve) ;;
    *) fail "Refusing an unexpected web directory: $NS_WEB" ;;
esac

[ "$(id -u)" = 0 ] || fail 'Run this as root on the router.'
[ -f /etc/openwrt_release ] || fail 'This is not OpenWrt.'

# Drops the scheduled scan from root's crontab, leaving every other line as it is.
unschedule() {
    [ -f "$CRONTAB" ] || return 0
    grep -vF "$TAG" "$CRONTAB" > "$CRONTAB.ns" || :
    mv -f "$CRONTAB.ns" "$CRONTAB"
}
restart_cron() {
    /etc/init.d/cron enable >/dev/null 2>&1 || :
    /etc/init.d/cron restart >/dev/null 2>&1 || note 'cron could not be restarted: the schedule starts after the next reboot.'
}

if [ "$NS_MODE" = remove ]; then
    unschedule
    restart_cron
    rm -rf "$DIR" "$NS_WEB"
    note 'The packages nodesieve needed stay installed. Remove them with opkg if nothing else uses them.'
    note "If Steer's main section is subscribed to the feed, connect it to another subscription or server list in the panel."
    printf '%s\n' 'NS_OK: nodesieve, its settings, feed and schedule were removed from the router.'
    exit 0
fi
[ "$NS_MODE" = install ] || fail "Unknown mode: $NS_MODE"

# 1. Packages
if command -v opkg >/dev/null 2>&1; then
    installed=$(opkg list-installed 2>/dev/null | cut -d' ' -f1)
    missing=''
    for package in $NS_PACKAGES; do
        printf '%s\n' "$installed" | grep -qxF "$package" || missing="$missing $package"
    done
    if [ -n "$missing" ]; then
        printf 'Installing%s\n' "$missing"
        opkg update >/tmp/nodesieve-packages.log 2>&1 \
            || fail 'opkg update failed: see /tmp/nodesieve-packages.log on the router.'
        # shellcheck disable=SC2086 # one word per package
        opkg install $missing >>/tmp/nodesieve-packages.log 2>&1 \
            || fail "Installing$missing failed: see /tmp/nodesieve-packages.log on the router."
    fi
elif command -v apk >/dev/null 2>&1; then
    # shellcheck disable=SC2086 # one word per package
    apk add $NS_PACKAGES >/tmp/nodesieve-packages.log 2>&1 \
        || fail 'Installing the packages failed: see /tmp/nodesieve-packages.log on the router.'
else
    fail 'The router has neither opkg nor apk to install packages with.'
fi
python3 -c 'import aiohttp, yaml' 2>/dev/null || fail 'Python or one of its modules does not work after installing.'

# 2. Code. Only what the archive holds is replaced: the settings, caches and the
# Xray and Mihomo binaries in the directory stay.
[ -s "$NS_ARCHIVE" ] || fail 'The code did not arrive on the router.'
rm -rf "$DIR.new"
mkdir -p "$DIR.new"
tar -xzf "$NS_ARCHIVE" -C "$DIR.new" || fail 'The code could not be unpacked.'
[ -f "$DIR.new/nodesieve/__main__.py" ] || fail 'The code arrived incomplete.'
mkdir -p "$DIR"
for item in "$DIR.new"/*; do
    name=${item##*/}
    case "$name" in
        nodesieve_config.json|feed|sub_cache|steer-output|xray|mihomo) continue ;;
    esac
    rm -rf "${DIR:?}/$name"
    mv "$item" "$DIR/$name"
done
rm -rf "$DIR.new"
# Earlier versions ran ipregion.sh for the location checks.
rm -f "$DIR/ipregion.sh"
chmod 700 "$DIR"

# 3. Settings, written only on the first install.
if [ -f "$DIR/nodesieve_config.json" ]; then
    info settings kept
else
    printf '%s\n' "$NS_SETTINGS" > "$DIR/nodesieve_config.json"
    info settings new
fi

# 4. The feed's directory. uhttpd serves only files anyone may read, and nodesieve writes
# the feed that way into a directory others may enter (711: enter, not list). index.html
# keeps uhttpd from listing the directory, and so the token, to the network.
feed_dir=$(jsonfilter -i "$DIR/nodesieve_config.json" -e '@.feed_dir' 2>/dev/null || :)
case "$feed_dir" in
    "$NS_WEB"/?*)
        mkdir -p "$feed_dir"
        chmod 711 "$NS_WEB" "$feed_dir"
        : > "$NS_WEB/index.html"
        chmod 644 "$NS_WEB/index.html"
        for file in "$feed_dir"/*; do [ ! -f "$file" ] || chmod 644 "$file"; done
        ;;
    '') note "The settings name no feed_dir, so the feed goes to $DIR/feed, where no web server serves it." ;;
    *) note "The settings put the feed in $feed_dir, outside $NS_WEB." ;;
esac
info feed_dir "$feed_dir"

# 5. Schedule
mkdir -p "${CRONTAB%/*}"
unschedule
if [ "$NS_EVERY" != 0 ]; then
    minute=$(( $(date +%s) % 60 ))
    case "$NS_EVERY" in
        1) hours='*' ;;
        24) hours=4 ;;
        *) hours="*/$NS_EVERY" ;;
    esac
    lock=''
    if command -v flock >/dev/null 2>&1; then lock='flock -n /var/lock/nodesieve.lock '; fi
    printf '%s %s * * * cd %s && PATH=/usr/sbin:/usr/bin:/sbin:/bin %spython3 -m nodesieve check > /tmp/nodesieve.log 2>&1 %s\n' \
        "$minute" "$hours" "$DIR" "$lock" "$TAG" >> "$CRONTAB"
    info schedule "$minute $hours * * *"
fi
restart_cron

info python "$(python3 --version 2>&1)"
printf 'NS_OK: nodesieve is installed in %s.\n' "$DIR"
}
ns_main
