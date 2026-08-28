#!/usr/bin/bash
set -euo pipefail

[[ $# == 1 ]] || { printf 'usage: %s <session-id>\n' "$0" >&2; exit 2; }
session_id=$1
[[ "$session_id" =~ ^[a-z0-9][a-z0-9-]{7,79}$ ]] || {
  printf 'launch-session refusal: invalid session id\n' >&2
  exit 2
}

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
custody="$repo/.campaign-local/gcl-v1"
worker="$custody/worker"
sessions="$custody/sessions"
session="$sessions/$session_id"
root_image="$worker/gcl-v1-worker-root.qcow2"
state_image="$worker/gcl-v1-worker-state.raw"
credential_image="$worker/gcl-v1-worker-credentials.raw"
known_hosts="$worker/known_hosts"
client_key="$worker/gcl-v1-worker-ssh"
client_public="$client_key.pub"
qemu=/usr/bin/qemu-system-x86_64
port=23022
unit="gcl-v1vm-${session_id}.service"
root_sha=f7cf2245cea7b691f817bf8a37362d795e832fda6e21ea5737722c0164940570
qemu_sha=8a35ccba41582fc6c38b9df85fc9e35fa1d42f414d2d7d8090ee9b2f5e7c0854

die() { printf 'launch-session refusal: %s\n' "$*" >&2; exit 1; }
[[ ! -e "$session" ]] || die 'session custody already exists'
[[ "$(sha256sum "$root_image" | cut -d' ' -f1)" == "$root_sha" ]] || die 'root image substitution'
[[ "$(sha256sum "$qemu" | cut -d' ' -f1)" == "$qemu_sha" ]] || die 'QEMU substitution'
for path in "$state_image" "$credential_image" "$known_hosts" "$client_key" "$client_public"; do
  [[ -f "$path" && ! -L "$path" ]] || die "missing exact worker input: $path"
done
[[ "$(stat -c %a "$root_image")" == 444 ]] || die 'root image is not host-read-only'
[[ "$(stat -c %a "$state_image")" == 600 ]] || die 'state device is not owner-only'
[[ "$(stat -c %a "$credential_image")" == 600 ]] || die 'credential device is not owner-only'
[[ "$(blkid -s LABEL -o value "$state_image")" == GCL_STATE ]] || die 'wrong state label'
[[ "$(blkid -s LABEL -o value "$credential_image")" == GCL_CREDENTIALS ]] || die 'wrong credential label'
systemctl --user is-active --quiet "$unit" && die 'unit is already active'
ss -ltn | awk '{print $4}' | grep -qx '127.0.0.1:23022' && die 'endpoint port is already in use'
[[ -z "$(git -C "$repo" status --porcelain)" ]] || die 'AG worktree is not clean'
ag_commit="$(git -C "$repo" rev-parse HEAD)"
ag_tree="$(git -C "$repo" rev-parse 'HEAD^{tree}')"


install -d -m 0700 "$sessions"
install -d -m 0700 "$session"
qmp="$session/qmp.sock"
serial="$session/serial.log"
pidfile="$session/qemu.pid"
qemu_argv=(
  "$qemu"
  -name "gcl-v1-${session_id},process=gcl-v1-${session_id}"
  -no-user-config
  -nodefaults
  -accel kvm
  -machine q35
  -cpu host
  -smp 4
  -m 6144
  -display none
  -monitor none
  -serial "file:$serial"
  -qmp "unix:$qmp,server=on,wait=off"
  -pidfile "$pidfile"
  -rtc base=utc
  -boot order=c,strict=on
  -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny
  -drive "if=virtio,file=$root_image,format=qcow2,readonly=on,cache=none,aio=native"
  -drive "if=virtio,file=$state_image,format=raw,cache=none,aio=native"
  -drive "if=virtio,file=$credential_image,format=raw,cache=none,aio=native"
  -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$port-:22"
  -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56
  -object rng-random,id=rng0,filename=/dev/urandom
  -device virtio-rng-pci,rng=rng0
  -smbios "type=1,serial=$session_id"
)
systemd_argv=(
  systemd-run
  --user
  "--unit=$unit"
  --service-type=exec
  --property=MemoryAccounting=yes
  --property=MemoryMax=8G
  --property=MemorySwapMax=0
  --property=CPUAccounting=yes
  --property=CPUQuota=400%
  --property=TasksAccounting=yes
  --property=TasksMax=512
  --property=IOAccounting=yes
  --property=KillMode=control-group
  --property=TimeoutStartSec=120s
  --property=TimeoutStopSec=30s
  --property=RuntimeMaxSec=12h
  --property=Restart=no
  --property=NoNewPrivileges=yes
  --property=UMask=0077
  "--working-directory=$session"
  --
  "${qemu_argv[@]}"
)
python3 - "$session/launch-spec.json" "$session_id" "$unit" "$ag_commit" "$ag_tree" \
  "$(sha256sum "$here/launch-session.sh" | cut -d' ' -f1)" "${systemd_argv[@]}" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
value = {
    "schema": "ag.gcl-v1-session-launch-spec/v1",
    "session_id": sys.argv[2],
    "unit": sys.argv[3],
    "capacity": 3,
    "ag_commit": sys.argv[4],
    "ag_tree": sys.argv[5],
    "launcher_sha256": sys.argv[6],
    "systemd_run_argv": sys.argv[7:],
}
path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
PY

started=0
cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [[ "$status" != 0 && "$started" == 1 ]]; then
    systemctl --user stop "$unit" >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

"${systemd_argv[@]}"
started=1
for _ in $(seq 1 60); do
  systemctl --user is-active --quiet "$unit" && [[ -S "$qmp" ]] && break
  systemctl --user is-failed --quiet "$unit" && die 'QEMU unit failed during startup'
  sleep 1
done
systemctl --user is-active --quiet "$unit" || die 'QEMU unit did not become active'
[[ -S "$qmp" ]] || die 'QMP socket did not appear'

ssh_argv=(
  /usr/bin/ssh -F /dev/null -p "$port" -i "$client_key"
  -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes
  -o "UserKnownHostsFile=$known_hosts" -o GlobalKnownHostsFile=/dev/null
  -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no
  -o PreferredAuthentications=publickey -o ClearAllForwardings=yes
  -o ControlMaster=no -o RequestTTY=no -o ConnectTimeout=5
  -o ConnectionAttempts=1 -- gcl-parent@127.0.0.1
  /usr/local/libexec/gcl-worker-agent identity
)
ready=0
for _ in $(seq 1 120); do
  if "${ssh_argv[@]}" >"$session/initial-identity.json.partial" 2>"$session/initial-identity.stderr"; then
    if python3 - "$session/initial-identity.json.partial" "$session_id" <<'PY'
import json, pathlib, sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text())
raise SystemExit(0 if value.get("session_id") == sys.argv[2] else 1)
PY
    then
      mv "$session/initial-identity.json.partial" "$session/initial-identity.json"
      ready=1
      break
    fi
  fi
  sleep 2
done
[[ "$ready" == 1 ]] || die 'pinned guest identity did not become ready'
trap - EXIT INT TERM
chmod 0600 "$session"/*
printf 'W3 session launched: %s\n' "$session_id"
printf 'Unit: %s\n' "$unit"
printf 'Custody: %s\n' "$session"
