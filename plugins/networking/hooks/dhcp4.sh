#!/bin/sh
# ifstate hook — manages a DHCPv4 client (dhclient) for an interface.
# Called by the ifstate hook wrapper with IFS_* env vars already exported.
# Return codes: IFS_RC_OK (0) = no change, IFS_RC_STARTED/STOPPED (2) = changed,
#               IFS_RC_ERROR (1) = failure.

PIDFILE="$IFS_RUNDIR/dhclient.pid"

case "$1" in
    start)
        if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
            exit $IFS_RC_OK
        fi
        dhclient -4 -pf "$PIDFILE" "$IFS_IFNAME"
        exit $IFS_RC_STARTED
        ;;
    check-start)
        if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
            exit $IFS_RC_OK
        fi
        exit $IFS_RC_STARTED
        ;;
    stop)
        if [ -f "$PIDFILE" ]; then
            dhclient -r -pf "$PIDFILE" "$IFS_IFNAME" 2>/dev/null || true
            rm -f "$PIDFILE"
            exit $IFS_RC_STOPPED
        fi
        exit $IFS_RC_OK
        ;;
    check-stop)
        if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
            exit $IFS_RC_STOPPED
        fi
        exit $IFS_RC_OK
        ;;
esac

exit $IFS_RC_ERROR
