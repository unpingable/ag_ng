# Managed-Pointer Preparation / Ratification Kernel

## Status

This note describes the first runtime campaign selected from the illegal-lifts
frontier census. It is a managed-pointer-specific composition of existing AG-ng
mechanisms. It is not a generic illegal-lifts framework, a Lean extraction, a
new effect family, or a claim that every atlas entry is implemented.

The runtime lifecycle is:

```text
bounded live preparation standing
-> exact candidate preparation in broker quarantine
-> protected authoritative projection re-observed unchanged
-> prepared candidate persisted with exact basis and complete inputs
-> canonical proposal binds that candidate
-> independent human ratification binds candidate and basis
-> fresh exact-basis observation mints live one-use promotion standing
-> authority burn
-> existing reversible object preparation and durable checkpoint
-> existing ref CAS
-> verified post-state, known no-effect failure, or reconciliation
```

## Census judgments mapped to Rust

| Judgment | Concrete runtime residence | Effect-boundary consequence |
| --- | --- | --- |
| Preparation needs bounded standing | Non-serializable `ManagedPointerPreparationStandingV1`; inspectable `ManagedPointerPreparationStandingReceiptV1` | Missing, foreign-profile, expired, or over-budget standing refuses before candidate preparation. A receipt cannot recreate the live value. |
| Every candidate has one exact basis | `ManagedPointerExactBasisV1` | Domain, epoch, target, catalog, profile, ref, repository layout/inodes, owner, object format, commit, tree, and prestate identity are candidate identity inputs. |
| Complete inputs are explicit without assuming determinism | `ManagedPointerCompleteInputsV1` | Artifact bytes/length, normalized pack, candidate commit/tree/parent, helper identity/profile, staging root, and budgets are digest-bound. Same inputs need not produce unique bytes. |
| Preparation declares bounded residue/effects | `ManagedPointerPreparationEffectsV1` and `ManagedPointerCandidatePreparationReceiptV1` | Pre-ratification work charges custody and quarantine bytes and declares zero target-object writes, ref writes, and network requests. The protected basis is observed before and after. |
| Byte equality does not imply candidate equality | `PreparedManagedPointerCandidateV1::identity` | Candidate identity includes the full basis, inputs, standing receipt, and preparation receipt. Identical artifact digests on different bases remain different candidates. |
| Ratification binds candidate and basis | `ManagedPointerCandidateRatificationV1` | The ratification record names proposal, candidate, basis, complete inputs, preparation receipt, and independent authorization. Substitution fails validation. |
| Current standing is separate from history | Non-serializable `ManagedPointerPromotionStandingV1`; evidence-only `ManagedPointerPromotionStandingReceiptV1` | Effectd reopens the repository and reconstructs standing only for the active ratification call. Restart retains history but cannot remint this value. |
| Basis mismatch is a refusal before burn | `ManagedPointerPromotionRefusalV1` in broker proposal record v2 | The broker persists the attempted authorization, candidate/basis binding, typed reason, and time while leaving the proposal `Ready` and the authorization unburned. |
| CAS proves coordination, not legitimacy | `ProposalStateV1` plus `ManagedPointerRuntimeV1::commit` | The production commit path is crate-private and accepts only a non-cloneable prepared value produced after live promotion standing. A `Ready` proposal has no transition directly to the CAS checkpoint. |

`BrokerProposalRecordV1` keeps its source-level name while its wire schema has
moved on; it now requires the explicit `ag.effect-broker-proposal/v3` schema,
and the direct inspection projection is `ag.effect-record/v3`. The Rust type
name is historical and carries no compatibility behaviour — there is no v1 or
v2 reader. Deserialized older records default their missing fields only so
validation can reject them with a typed store corruption boundary; they are
never migrated by inference. A managed-pointer
record must carry exactly one matching prepared candidate. The expanded nested
canonical promotion contract is explicitly
`ag.managed-pointer-promotion/v2`; old `/v1` payloads cannot enter the new
executor under a reused schema name. The expanded reversible-preparation
checkpoint is likewise `ag.managed-pointer.preparation/v2` because it now binds
candidate-ratification and live-standing evidence.

## Hostile evidence

The campaign tests these forcing cases:

1. `byte_identical_candidates_on_different_bases_do_not_share_ratification` keeps artifact bytes equal while basis and candidate identities differ.
2. `post_ratification_candidate_content_or_metadata_substitution_refuses` mutates content and launch metadata after ratification.
3. `ref_drift_after_canonicalization_is_a_known_no_effect_failure` records a typed current-basis refusal before authority burn and leaves the foreign target untouched.
4. `mechanical_cas_success_is_not_an_authority_transition` proves the lifecycle has no `Ready -> CommitMayProceed` edge.
5. `candidate_preparation_requires_live_scope_and_budget_standing` covers absent standing, profile/scope mismatch, and budget exhaustion.
6. The byte-identical/different-basis fixture also presents the correct artifact under the wrong basis and rejects ratification transport.
7. `restart_preserves_candidate_history_without_reminting_promotion_standing`
   reloads a prepared but unratified candidate without inventing ratification,
   while `restart_preserves_ratification_history_without_reexecution` reloads
   the terminal candidate and exact ratification history and proves replay
   cannot reconstruct standing or execute the CAS again.

The existing managed-pointer integration additionally verifies the successful
candidate/basis ratification binding through the real target-owner ref-CAS path.

## Honest gaps

- Quarantine accounting charges exact artifact and normalized-pack bytes, but
  this campaign does not install a filesystem project quota for temporary Git
  metadata. The staging root remains broker-owned and bounded by existing
  process, input, and Git-output limits.
- The protected authoritative projection is the enrolled repository layout and
  managed ref state. This is not a generic commutation claim about all host
  state.
- Human exact ratification is the broker-integrated path in this slice. The
  existing derived-promotion library is not newly wired into this lifecycle.
- Preparation history is durable evidence, not present authority. Backup,
  restore, epoch rotation, and copied-state replay remain separate authority-
  resurrection campaigns.
- No deterministic-construction premise or artifact-byte uniqueness claim is
  made.
- Real power-loss qualification and production filesystem quota enforcement
  remain release blockers; green tests do not establish production readiness.
