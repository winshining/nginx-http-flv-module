#!/bin/sh
set -eu

origin=http://127.0.0.1:8080
stream=rtmp://127.0.0.1:1935/ingest
cd /captures
test "$(stat -f -c %T .)" = tmpfs && test -z "$(ls -A)" || exit 1
chown nobody .

control() {
    status=$(curl -sS --max-time 2 -o /dev/null -w '%{http_code}' \
        "$origin/control/record/$2?app=ingest&name=source&rec=audio&key=$3")
    if [ "$status" != "$1" ]; then
        echo "$2 $3: expected HTTP $1, received $status" >&2
        exit 1
    fi
}

wait_for() {
    for attempt in $(seq 1 100); do
        if "$@"; then return; fi
        sleep 0.05
    done
    echo "Timed out: $*" >&2
    exit 1
}
connected() { curl -fsS --max-time 1 "$origin/stats" | grep -q '<publishing/>'; }
offline() { ! connected; }
publish_clip() {
    ffmpeg -nostdin -v error -i "$1" -c:a copy -f flv "$stream/$2"
    wait_for offline
}
packets() {
    ffprobe -v error -select_streams a -show_packets -show_data_hash sha256 \
        -show_entries packet=data_hash:packet_side_data= -of default=nk=1:nw=1 "$1"
}

nginx -t -c /check/nginx.conf
nginx -c /check/nginx.conf
for hz in 440 880; do
    ffmpeg -nostdin -v error -f lavfi -i "sine=frequency=$hz:duration=0.4" \
        -c:a aac -f flv "$hz.flv"
    packets "$hz.flv" >> expected
done
publish_clip 440.flv reconnect
publish_clip 880.flv reconnect
# Only timestamps and container headers may change across a reconnect.
packets session-A.flv > actual
diff -u expected actual
control 204 stop session-A

printf 'incomplete source' > broken.flv
chown nobody broken.flv
publish_clip 440.flv damaged
test "$(cat broken.flv)" = 'incomplete source'
packets 440.flv > expected
packets broken.part1.flv > actual
diff -u expected actual

ffmpeg -nostdin -v error -re -stream_loop -1 -i 440.flv -c:a copy \
    -f flv "$stream/manual" &
publisher=$!
trap 'kill -TERM "$publisher" 2>/dev/null || :; wait "$publisher" 2>/dev/null || :' EXIT
wait_for connected
test ! -e source.flv
control 400 start bad.key
control 200 start session-B
wait_for test -s session-B.flv
control 200 start session-B
control 409 start session-A
control 204 stop session-A
control 200 stop session-B
control 204 stop session-B

exec 9>locked.flv
chown nobody locked.flv
flock -n 9
control 500 start locked
test ! -e locked.part1.flv
timeout 5 ffmpeg -nostdin -v error -analyzeduration 100000 -probesize 2048 \
    -i "$stream/source" -t 0.2 -f null -
printf '%s\n' 'PASS: keyed control, packet-exact append, damaged and locked sources, live playback'
