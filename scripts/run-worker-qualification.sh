#!/bin/sh
# Run the live worker ingress qualification suite.
#
# This suite is not part of `cargo test --workspace` and not part of the packaged
# test step. It launches a real ELF worker under real bubblewrap confinement
# against a real Git repository, so it needs host prerequisites that a package
# builder cannot guarantee. See docs/worker-qualification.md.
#
# Exit codes follow scripts/verify-effectd-isolation.sh:
#   0  qualified
#   1  the suite failed
#   2  a prerequisite is unmet, so the suite was not run
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository_root"

for required_executable in /usr/bin/bwrap /usr/bin/git
do
    if [ ! -x "$required_executable" ]
    then
        echo "worker qualification requires $required_executable" >&2
        exit 2
    fi
done

# Bubblewrap here is not setuid; it needs unprivileged user namespaces. Probe the
# real mechanism rather than reading a sysctl, because containerised builders can
# report the sysctl enabled and still refuse the clone.
if ! /usr/bin/bwrap \
    --ro-bind /usr /usr \
    --symlink usr/lib /lib \
    --symlink usr/lib64 /lib64 \
    --unshare-all \
    /usr/bin/true >/dev/null 2>&1
then
    echo "worker qualification requires unprivileged user namespaces" >&2
    echo "  (bubblewrap could not create a sandbox on this host)" >&2
    exit 2
fi

# The suite binds Unix sockets under TMPDIR, and the kernel bounds sun_path at
# 108 bytes. The longest path the suite builds adds 50 bytes to TMPDIR, so fail
# here with the budget rather than partway through a test.
temporary_directory=${TMPDIR:-/tmp}
temporary_directory_length=$(printf '%s' "$temporary_directory" | wc -c)
if [ "$temporary_directory_length" -gt 57 ]
then
    echo "worker qualification requires TMPDIR at most 57 bytes; TMPDIR is" \
        "$temporary_directory_length bytes: $temporary_directory" >&2
    echo "  (the kernel limits sun_path to 108 bytes and the suite adds 50)" >&2
    exit 2
fi

if ! cargo test \
    --locked \
    --offline \
    --package ag-app \
    --features worker-fixture \
    --test worker_live_ingress
then
    echo "worker qualification failed" >&2
    exit 1
fi

echo "worker qualification verified: live worker ingress admitted only through signed candidates"
