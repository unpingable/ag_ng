# Current native production-lifecycle packet fixture

`modern-glass-heron-packet.v1.json` is the modern packet emitted by the existing
`qualification/governed-campaign-loop-v1/velvet-pigeon/build_specimen.py`, not a
schema-string edit of the historical frozen packet. Reservations, template
digests and packet identity were recomputed by that generator. Its provider,
session and realization inputs are explicitly synthetic contract specimens:
they do not establish a live worker run or enrolled session custody.

Captured in CLASSIC-RETIREMENT `stage-integrated-003-velvet`, generator source
AGbf6adde2792a886d1ba75d97ca77efb8e914f4f5, native runtime NQ022419593b1065da7e83802d1fb6efc77362f6a1,
Nightshiftbb147e3c475da002d80b139d837b6fa9989fe242. The actual modern native
evaluation/replay/retention and AG crossing passed with classic trees unavailable.
The production-lifecycle tests separately validate this exact packet and retain
all their original positive/refusal/continuation assertions.

Regenerate into a new `RETIREMENT_SPECIMEN_OUT` with explicit `NQ_NG_BIN`,
`NIGHTSHIFT_BIN`, and `NIGHTSHIFT_RESOLVER_BIN` as documented in the existing
generator recipe; compare its `glass-heron-packet.v1.json` before updating this
fixture. Do not regenerate or overwrite the historical packet under
`qualification/governed-campaign-loop-v1/velvet-pigeon/evidence/`.
