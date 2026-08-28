# W1 image derivation attempts

All attempts used real KVM acceleration. Incomplete images and writable devices
were retained outside Git under the ignored local custody root; they are not
admissible session inputs.

1. `failed-build-1` reached the pinned post-provision endpoint and refused
   identity because Ubuntu exposes the SMBIOS product serial only to root. The
   contract was corrected to have the root init validate and publish only that
   serial as a read-only `/run` fact.
2. `failed-build-2` proved the root was read-only and both labeled writable
   devices were mounted, then refused init because the recipe tried to refresh
   metadata on already-immutable home directories. Those redundant operations
   were removed.
3. The admitted derivation rebooted successfully, returned the frozen identity,
   shut down through QMP, and converted to one standalone qcow2 with no backing
   image. Its exact identities are in `w1-image-build.json`.

Neither failed derivation authenticated Codex or carried campaign work.
