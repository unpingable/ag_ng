# Hand-authoring a standing mandate store

The daemon's only independent authority input is a root-owned
`ag.governed-loop.standing-mandate-store/v1` JSON document
(`ag_app::standing_authority::StandingMandateStoreV1`). To hand-author one:

1. The top-level object has exactly two fields: `schema` (the exact string
   above) and `mandates` (an array).
2. Each mandate has exactly five fields (`deny_unknown_fields` is enforced):
   - `subject`, `scope`: canonical `sha256:<64 lowercase hex>` digests equal
     to the request's `subject_digest` / `scope_digest`.
   - `generation`: a monotonic `u64` within one `(subject, scope)` pair.
   - `status`: `"active"` or `"revoked"`.
   - `valid_until_unix_ms`: exclusive end of validity; a mandate with
     `valid_until <= now` is **expired** (equality is expired).
3. `mandates` must be in strict ascending `(subject, scope, generation)`
   order (digests compare as their canonical strings). Duplicates or
   out-of-order records make the whole store a load error, and the daemon
   then fails closed with an infrastructure error — never a refusal.
4. Standing resolution for one request answers over the **highest
   generation** for the exact `(subject, scope)`: no mandate → `absent`;
   expired → `standing_not_current`; revoked → `standing_not_current`;
   otherwise `Current`, with the answer expiry clipped to
   `min(now + answer_ttl_ms, valid_until_unix_ms)`.
5. The file is re-read and re-validated on every request; mandates change
   out of band by atomically replacing the file. Deployment custody is
   same-UID local only (regular file, owned by the daemon's effective UID,
   never a symlink) — there is no cryptographic authentication.

The test helper `tests/common/mod.rs::write_standing_store` constructs and
serializes conformant stores; see it for a minimal example.
