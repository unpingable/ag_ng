#!/usr/bin/bash
set -euo pipefail

[[ "$(id -u)" == 0 ]] || { printf 'provisioning requires root\n' >&2; exit 1; }
source_dir="$(cd "$(dirname "$0")" && pwd)"
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates git nftables openssh-server uidmap util-linux
apt-get clean
rm -rf /var/lib/apt/lists/*

id gcl-parent >/dev/null 2>&1 ||
  useradd --uid 2000 --user-group --create-home --home-dir /home/gcl-parent \
    --shell /bin/bash gcl-parent
id gcl-workload >/dev/null 2>&1 ||
  useradd --uid 2001 --user-group --create-home --home-dir /home/gcl-workload \
    --shell /usr/sbin/nologin gcl-workload
[[ "$(id -u gcl-parent):$(id -g gcl-parent)" == 2000:2000 ]]
[[ "$(id -u gcl-workload):$(id -g gcl-workload)" == 2001:2001 ]]

install -d -m 0755 -o root -g root /usr/local/libexec/gcl/codex-resources
install -m 0755 -o root -g root "$source_dir/codex" /usr/local/libexec/gcl/codex
install -m 4755 -o root -g root "$source_dir/bwrap" \
  /usr/local/libexec/gcl/codex-resources/bwrap
ln -f /usr/local/libexec/gcl/codex-resources/bwrap /usr/local/libexec/gcl/bwrap
install -m 0755 -o root -g root "$source_dir/gcl-worker-agent.py" \
  /usr/local/libexec/gcl-worker-agent
install -m 0755 -o root -g root "$source_dir/gcl-worker-shell" \
  /usr/local/libexec/gcl-worker-shell
install -m 0755 -o root -g root "$source_dir/gcl-worker-init" \
  /usr/local/libexec/gcl-worker-init
ln -sfn /usr/local/libexec/gcl-worker-shell /usr/local/bin/bash

install -d -m 0700 -o gcl-parent -g gcl-parent /home/gcl-parent/.ssh
install -m 0600 -o gcl-parent -g gcl-parent "$source_dir/authorized_key" \
  /home/gcl-parent/.ssh/authorized_keys
cat >/etc/ssh/sshd_config.d/70-gcl-worker.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers gcl-parent
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no
GatewayPorts no
PermitUserEnvironment no
ClientAliveInterval 15
ClientAliveCountMax 2
Match User gcl-parent
    AuthenticationMethods publickey
EOF
sshd -t

cat >/etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
flush ruleset
table inet gcl_worker {
  chain input {
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    ct state established,related accept
    ip protocol icmp accept
    tcp dport 22 accept
  }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    ct state established,related accept
    ip daddr 10.0.2.2 reject
    udp sport 68 udp dport 67 accept
    udp dport 53 accept
    tcp dport 53 accept
    udp dport 123 accept
    meta skuid 2000 tcp dport 443 accept
  }
}
EOF
systemctl enable nftables.service

install -d -m 0755 /var/lib/gcl-state /var/lib/gcl-credentials
grep -q 'LABEL=GCL_STATE ' /etc/fstab ||
  printf 'LABEL=GCL_STATE /var/lib/gcl-state ext4 defaults,nodev,nosuid,noexec 0 2\n' >>/etc/fstab
grep -q 'LABEL=GCL_CREDENTIALS ' /etc/fstab ||
  printf 'LABEL=GCL_CREDENTIALS /var/lib/gcl-credentials ext4 defaults,nodev,nosuid,noexec 0 2\n' >>/etc/fstab
sed -Ei '/^[^#]+[[:space:]]+\/[[:space:]]+/{ /[[:space:]]ro[,[:space:]]/! s/([[:space:]][^[:space:]]+)([[:space:]]+[0-9]+[[:space:]]+[0-9]+)$/\1,ro\2/; }' /etc/fstab

cat >/etc/systemd/system/gcl-worker-init.service <<'EOF'
[Unit]
Description=Initialize the exact GCL V1 worker devices
RequiresMountsFor=/var/lib/gcl-state /var/lib/gcl-credentials
After=local-fs.target
Before=ssh.service

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/gcl-worker-init
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl enable gcl-worker-init.service ssh.service

if grep -q '^GRUB_CMDLINE_LINUX=' /etc/default/grub; then
  sed -Ei 's/^(GRUB_CMDLINE_LINUX=")([^"]*)"/\1\2 ro systemd.volatile=state ipv6.disable=1"/' /etc/default/grub
else
  printf 'GRUB_CMDLINE_LINUX="ro systemd.volatile=state ipv6.disable=1"\n' >>/etc/default/grub
fi
update-grub

touch /etc/cloud/cloud-init.disabled
systemctl mask apt-daily.service apt-daily-upgrade.service \
  apt-daily.timer apt-daily-upgrade.timer cloud-init.service \
  cloud-config.service cloud-final.service cloud-init-local.service
passwd -l ubuntu || true
install -d -m 0755 /usr/local/share/gcl-worker
dpkg-query -W -f='${binary:Package}\t${Version}\n' | LC_ALL=C sort \
  >/usr/local/share/gcl-worker/packages.tsv
sha256sum \
  /usr/local/libexec/gcl/codex \
  /usr/local/libexec/gcl/bwrap \
  /usr/local/libexec/gcl-worker-agent \
  /usr/local/libexec/gcl-worker-shell \
  /usr/local/libexec/gcl-worker-init \
  /etc/nftables.conf \
  /etc/ssh/sshd_config.d/70-gcl-worker.conf \
  /etc/systemd/system/gcl-worker-init.service \
  >/usr/local/share/gcl-worker/immutable.sha256
sync
