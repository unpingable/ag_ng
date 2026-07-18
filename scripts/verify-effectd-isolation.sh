#!/bin/sh
# Verify the exact production effect-broker build has no provider network stack.
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository_root"

dependency_graph=$(mktemp)
trap 'rm -f "$dependency_graph"' EXIT HUP INT TERM

cargo tree \
    --locked \
    --offline \
    --package ag-app \
    --edges normal,build \
    --prefix none \
    --format '{p}' >"$dependency_graph"

# This is deliberately a closed denylist in addition to the package boundary.
# It catches accidental introduction of the provider crate or a replacement
# HTTP/TLS stack into the package that produces ag-effectd.
for forbidden_crate in \
    ag-providerd \
    reqwest \
    hyper \
    hyper-util \
    hyper-rustls \
    rustls \
    rustls-pki-types \
    rustls-webpki \
    tokio-rustls \
    h2 \
    tower-http \
    native-tls \
    openssl \
    openssl-sys \
    curl \
    curl-sys \
    ureq \
    surf \
    isahc \
    quinn \
    quinn-proto \
    quinn-udp
do
    if awk -v package="$forbidden_crate" '$1 == package { found = 1 } END { exit !found }' \
        "$dependency_graph"
    then
        echo "effectd isolation violation: forbidden dependency $forbidden_crate" >&2
        exit 1
    fi
done

cargo build --locked --offline --release --package ag-app --bin ag-effectd

if ! command -v strings >/dev/null 2>&1 || ! command -v readelf >/dev/null 2>&1
then
    echo "effectd isolation verification requires strings and readelf" >&2
    exit 2
fi

effectd_artifact=${CARGO_TARGET_DIR:-target}/release/ag-effectd
if [ ! -x "$effectd_artifact" ]
then
    echo "effectd isolation verification did not find $effectd_artifact" >&2
    exit 2
fi

if ! readelf --file-header "$effectd_artifact" >/dev/null 2>&1
then
    echo "effectd isolation verification requires an ELF ag-effectd artifact" >&2
    exit 2
fi

for forbidden_shared_object in \
    'libcurl.so' \
    'libssl.so' \
    'libcrypto.so' \
    'libnghttp2.so' \
    'libssh2.so'
do
    if readelf --dynamic "$effectd_artifact" | grep -F -q "$forbidden_shared_object"
    then
        echo "effectd isolation violation: artifact loads $forbidden_shared_object" >&2
        exit 1
    fi
done

# The graph is the normative check. This second check catches an accidentally
# injected static object or linker input that Cargo metadata cannot describe.
for forbidden_artifact_token in \
    'reqwest::' \
    'hyper::' \
    'hyper_util::' \
    'hyper_rustls::' \
    'rustls::' \
    'tokio_rustls::' \
    'ag_providerd::' \
    '/crates/ag-providerd/src/'
do
    if LC_ALL=C strings -a "$effectd_artifact" | grep -F -q "$forbidden_artifact_token"
    then
        echo "effectd isolation violation: artifact contains $forbidden_artifact_token" >&2
        exit 1
    fi
done

echo "effectd isolation verified: dependency graph and release artifact are provider-network-free"
