#!/usr/bin/bash
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
custody="$repo/.campaign-local/gcl-v1"
downloads="$custody/downloads"
root_only="${GCL_ROOT_ONLY_REBUILD:-0}"
root_revision="${GCL_ROOT_REBUILD_REVISION:-r1}"
build="$custody/build"
outputs="$custody/worker"
release=20260826
image_name=ubuntu-24.04-server-cloudimg-amd64.img
base_url="https://cloud-images.ubuntu.com/releases/releases/noble/release-${release}"
base_image="$downloads/$image_name"
checksums="$downloads/SHA256SUMS"
root_image="$outputs/gcl-v1-worker-root.qcow2"
state_image="$outputs/gcl-v1-worker-state.raw"
credential_image="$outputs/gcl-v1-worker-credentials.raw"
client_key="$outputs/gcl-v1-worker-ssh"
known_hosts="$outputs/known_hosts"
if [[ "$root_only" == 1 ]]; then
  [[ "$root_revision" =~ ^r[1-9][0-9]*$ ]] || {
    printf 'build-worker-image refusal: invalid root rebuild revision\n' >&2
    exit 1
  }
  build="$custody/build-root-$root_revision"
  root_image="$outputs/gcl-v1-worker-root-$root_revision.qcow2"
  known_hosts="$outputs/known_hosts-$root_revision"
fi
port=23022
codex=/home/jbeck/.nvm/versions/node/v24.13.0/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex
bwrap=/home/jbeck/.nvm/versions/node/v24.13.0/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/codex-resources/bwrap
codex_sha=cb0a15567e9a60a5820d54b0f6ae86d504dc3805c1eab21a47f70e3eb7b73a40
bwrap_sha=77360cb751ccedc5971391444ac86a8a33c15b04d6b4a6fe45f5d25496e62c4c

die() { printf 'build-worker-image refusal: %s\n' "$*" >&2; exit 1; }
for command in curl qemu-img qemu-system-x86_64 xorriso ssh ssh-keygen scp mkfs.ext4; do
  command -v "$command" >/dev/null || die "missing command: $command"
done
[[ -r /dev/kvm && -w /dev/kvm ]] || die '/dev/kvm is not usable'
[[ "$(sha256sum "$codex" | cut -d' ' -f1)" == "$codex_sha" ]] || die 'Codex identity mismatch'
[[ "$(sha256sum "$bwrap" | cut -d' ' -f1)" == "$bwrap_sha" ]] || die 'Bubblewrap identity mismatch'
if [[ "$root_only" == 1 ]]; then
  [[ ! -e "$root_image" && ! -e "$known_hosts" ]] ||
    die 'root-only repair output already exists'
  [[ -f "$state_image" && -f "$credential_image" &&
     -f "$client_key" && -f "$client_key.pub" ]] ||
    die 'root-only repair requires existing state, credential, and client identities'
  [[ "$(blkid -s LABEL -o value "$state_image")" == GCL_STATE &&
     "$(blkid -s LABEL -o value "$credential_image")" == GCL_CREDENTIALS ]] ||
    die 'root-only repair device labels mismatch'
else
  [[ ! -e "$root_image" && ! -e "$state_image" && ! -e "$credential_image" ]] ||
    die 'worker output already exists'
  [[ ! -e "$client_key" && ! -e "$client_key.pub" && ! -e "$known_hosts" ]] ||
    die 'worker SSH custody already exists'
fi

mkdir -p "$downloads" "$build" "$outputs"
chmod 0700 "$custody" "$build" "$outputs"
curl --fail --location --proto '=https' --tlsv1.2 \
  --output "$checksums" "$base_url/SHA256SUMS"
if [[ ! -e "$base_image" ]]; then
  curl --fail --location --proto '=https' --tlsv1.2 \
    --output "$base_image.partial" "$base_url/$image_name"
  mv "$base_image.partial" "$base_image"
fi
expected="$(awk -v name="*$image_name" '$2 == name {print $1}' "$checksums")"
[[ "$expected" =~ ^[0-9a-f]{64}$ ]] || die 'official image checksum is absent'
observed="$(sha256sum "$base_image" | cut -d' ' -f1)"
[[ "$observed" == "$expected" ]] || die 'official image checksum mismatch'

if [[ "$root_only" != 1 ]]; then
  ssh-keygen -q -t ed25519 -N '' -C gcl-v1-worker-exact-endpoint -f "$client_key"
fi
chmod 0600 "$client_key"
seed="$build/seed"
mkdir -p "$seed"
public_key="$(cat "$client_key.pub")"
printf '%s\n' \
  '#cloud-config' \
  'ssh_pwauth: false' \
  'disable_root: true' \
  'users:' \
  '  - name: ubuntu' \
  '    groups: [adm, sudo]' \
  '    sudo: ALL=(ALL) NOPASSWD:ALL' \
  '    shell: /bin/bash' \
  '    lock_passwd: true' \
  "    ssh_authorized_keys: [$public_key]" >"$seed/user-data"
printf 'instance-id: gcl-v1-worker-image-build-%s\nlocal-hostname: gcl-v1-worker-build\n' \
  "$release" >"$seed/meta-data"
(
  cd "$seed"
  xorriso -as mkisofs -quiet -output "$build/seed.iso" \
    -volid cidata -joliet -rock user-data meta-data
)

qemu-img create -q -f qcow2 -F qcow2 -b "$base_image" "$build/root-overlay.qcow2" 32G
if [[ "$root_only" != 1 ]]; then
  qemu-img create -q -f raw "$state_image" 12G
  qemu-img create -q -f raw "$credential_image" 1G
  mkfs.ext4 -q -F -L GCL_STATE "$state_image"
  chmod 0600 "$state_image" "$credential_image"
  mkfs.ext4 -q -F -L GCL_CREDENTIALS "$credential_image"
fi

qmp="$build/build.qmp"
serial="$build/serial.log"
qemu_argv=(
  /usr/bin/qemu-system-x86_64
  -name gcl-v1-worker-image-build
  -accel kvm
  -machine q35
  -cpu host
  -smp 4
  -m 6144
  -nodefaults
  -display none
  -monitor none
  -serial "file:$serial"
  -qmp "unix:$qmp,server=on,wait=off"
  -drive "if=virtio,file=$build/root-overlay.qcow2,format=qcow2,cache=none"
  -drive "if=virtio,file=$state_image,format=raw,cache=none"
  -drive "if=virtio,file=$credential_image,format=raw,cache=none"
  -drive "if=none,id=seed,file=$build/seed.iso,format=raw,readonly=on"
  -device ide-cd,drive=seed
  -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$port-:22"
  -device virtio-net-pci,netdev=net0
  -device virtio-rng-pci
  -smbios type=1,serial=gcl-v1-image-build
)
{
  printf '%q' "${qemu_argv[0]}"
  printf ' %q' "${qemu_argv[@]:1}"
  printf '\n'
} >"$build/qemu-command.txt"
"${qemu_argv[@]}" &
qemu_pid=$!
cleanup() {
  if kill -0 "$qemu_pid" 2>/dev/null; then
    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT

bootstrap_ssh=(
  ssh -p "$port" -i "$client_key"
  -o IdentitiesOnly=yes
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o ConnectTimeout=5
  -o ConnectionAttempts=1
)
bootstrap_scp=(
  scp -P "$port" -i "$client_key"
  -o IdentitiesOnly=yes
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
)
ready=0
for _ in $(seq 1 120); do
  if "${bootstrap_ssh[@]}" ubuntu@127.0.0.1 true >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 5
done
[[ "$ready" == 1 ]] || die 'bootstrap SSH did not become ready'

"${bootstrap_ssh[@]}" ubuntu@127.0.0.1 'mkdir -m 700 /tmp/gcl-provision'
"${bootstrap_scp[@]}" \
  "$codex" "$bwrap" "$client_key.pub" \
  "$here/guest/gcl-worker-agent.py" \
  "$here/guest/gcl-worker-shell" \
  "$here/guest/gcl-worker-init" \
  "$here/guest/provision-worker.sh" \
  ubuntu@127.0.0.1:/tmp/gcl-provision/
"${bootstrap_ssh[@]}" ubuntu@127.0.0.1 \
  'cd /tmp/gcl-provision && mv gcl-v1-worker-ssh.pub authorized_key && sudo /usr/bin/bash ./provision-worker.sh'
"${bootstrap_ssh[@]}" ubuntu@127.0.0.1 'sudo systemctl reboot' || true

ready=0
for _ in $(seq 1 120); do
  if ssh-keyscan -T 3 -p "$port" 127.0.0.1 >"$known_hosts.partial" 2>/dev/null &&
     grep -q 'ssh-ed25519' "$known_hosts.partial"; then
    mv "$known_hosts.partial" "$known_hosts"
    chmod 0600 "$known_hosts"
    if ssh -p "$port" -i "$client_key" -o IdentitiesOnly=yes \
      -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts" \
      -o BatchMode=yes -o ConnectTimeout=5 -o ConnectionAttempts=1 \
      -o ServerAliveInterval=15 -o ServerAliveCountMax=2 \
      gcl-parent@127.0.0.1 /usr/local/libexec/gcl-worker-agent identity \
      >"$build/identity.json"; then
      ready=1
      break
    fi
  fi
  sleep 5
done
[[ "$ready" == 1 ]] || die 'pinned worker endpoint did not become ready'

runtime_scp=(
  scp -P "$port" -i "$client_key"
  -o IdentitiesOnly=yes
  -o StrictHostKeyChecking=yes
  -o UserKnownHostsFile="$known_hosts"
  -o BatchMode=yes
  -o ConnectTimeout=5
  -o ConnectionAttempts=1
  -o ServerAliveInterval=15
  -o ServerAliveCountMax=2
)
"${runtime_scp[@]}" \
  gcl-parent@127.0.0.1:/usr/local/share/gcl-worker/packages.tsv \
  "$build/packages.tsv"
"${runtime_scp[@]}" \
  gcl-parent@127.0.0.1:/usr/local/share/gcl-worker/immutable.sha256 \
  "$build/immutable.sha256"

python3 - "$qmp" <<'PY'
import json, socket, sys, time
path = sys.argv[1]
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
for _ in range(100):
    try:
        sock.connect(path)
        break
    except OSError:
        time.sleep(.1)
else:
    raise SystemExit("QMP socket unavailable")
stream = sock.makefile("rwb", buffering=0)
stream.readline()
for command in ({"execute": "qmp_capabilities"}, {"execute": "system_powerdown"}):
    stream.write((json.dumps(command) + "\n").encode())
    while True:
        response = json.loads(stream.readline())
        if "return" in response or "error" in response:
            break
sock.close()
PY
for _ in $(seq 1 60); do
  kill -0 "$qemu_pid" 2>/dev/null || break
  sleep 1
done
kill -0 "$qemu_pid" 2>/dev/null && die 'guest did not power down cleanly'
wait "$qemu_pid"
trap - EXIT

qemu-img convert -p -f qcow2 -O qcow2 "$build/root-overlay.qcow2" "$root_image.partial"
mv "$root_image.partial" "$root_image"
chmod 0444 "$root_image"
qemu-img info --output=json --backing-chain "$root_image" >"$build/root-image-info.json"
root_sha="$(sha256sum "$root_image" | cut -d' ' -f1)"
state_uuid="$(blkid -s UUID -o value "$state_image")"
credential_uuid="$(blkid -s UUID -o value "$credential_image")"
host_key_fingerprint="$(ssh-keygen -lf "$known_hosts" | awk 'NR == 1 {print $2}')"
qemu_sha="$(sha256sum /usr/bin/qemu-system-x86_64 | cut -d' ' -f1)"
python3 - "$build/build-receipt.json" <<PY
import json, pathlib
receipt = {
  "schema": "ag.gcl-v1-worker-image-build/v1",
  "root_only_rebuild": $([[ "$root_only" == 1 ]] && printf True || printf False),
  "release": "$release",
  "source_url": "$base_url/$image_name",
  "source_sha256": "$observed",
  "checksum_manifest_sha256": "$(sha256sum "$checksums" | cut -d' ' -f1)",
  "root_image_sha256": "$root_sha",
  "state_device_uuid": "$state_uuid",
  "credential_device_uuid": "$credential_uuid",
  "guest_host_key_fingerprint": "$host_key_fingerprint",
  "codex_sha256": "$codex_sha",
  "bwrap_sha256": "$bwrap_sha",
  "qemu_executable": "/usr/bin/qemu-system-x86_64",
  "qemu_sha256": "$qemu_sha",
  "network_endpoint": "127.0.0.1:$port",
  "capacity": 3,
}
path = pathlib.Path("$build/build-receipt.json")
path.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
PY
sha256sum \
  "$build/build-receipt.json" "$build/identity.json" "$build/packages.tsv" \
  "$build/immutable.sha256" "$build/qemu-command.txt" "$build/root-image-info.json" \
  >"$build/evidence.sha256"
printf 'W1 image built: %s\n' "$root_sha"
printf 'Local custody: %s\n' "$custody"
