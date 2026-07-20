# Clean-host qualification fixtures

This directory is the source-side controller contract for the campaign in
`docs/clean-host-activation-qualification.md`. It is not a qualification
receipt and contains no passing host evidence.

`claim.v1.json` is the frozen claim/exclusion split. `matrix.toml` names the
mandatory guests and case families. `receipt.template.v1.json` uses a distinct
`receipt-template/v1` schema, carries all four guest cells and every mandatory
case result as `not_run`, and names the eventual `receipt/v1` target schema. It
is intentionally not a valid final receipt.

Validate the source contract without root or third-party Python packages:

```text
python3 qualification/clean-host/validate.py
python3 -m unittest discover -s qualification/clean-host -p 'test_*.py'
```

A controller implementation must create a fresh VM or restore the named
snapshot for each hostile case, enforce bounded deadlines, and copy evidence
out before destroying the guest. Containers are not acceptable substitutes
for the systemd, mount, capability, Landlock, and package-lifecycle boundary.

Receipts belong under `qualification/receipts/clean-host/` only after every
mandatory cell has run. The aggregate must be a separate receipt-only commit
whose source/harness/package/image digests refer backward to immutable inputs.
Private fixture signing keys must never be copied into evidence.
