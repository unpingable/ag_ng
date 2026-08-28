# Governed Campaign Loop V1 worker qualification

This directory contains reviewable recipes and scrubbed receipts for the one
Crow worker-VM profile. Large VM images, writable devices, SSH private keys,
credentials, full Codex transcripts, and campaign quarantine objects live only
under the ignored `.campaign-local/gcl-v1/` custody root.

Ordered entry points:

1. `build-worker-image.sh` downloads and independently derives the immutable
   worker root and initializes fresh writable state devices.
2. `launch-session.sh` launches one exact measured transient systemd unit.
3. `freeze-session.py` emits a credential-free session manifest.
4. Later qualification harnesses consume that exact manifest; they do not
   rediscover or select a VM.

No file in this directory is authority. Qualification still flows through the
unchanged NQ, Nightshift, and AG offices after an exact candidate is applied.
