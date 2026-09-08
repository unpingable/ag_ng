# Operator-beta AG store-cut package V1 qualification

Status: **CANDIDATE_FOR_INDEPENDENT_REVIEW**

This qualification is deliberately package-local. It binds one inert Debian
archive to accepted AG owner subject `837de287497942c79966aa05c083acee9c312261`
and proves that the archive exposes the read-only `audit-store` interface
without adding installation lifecycle or authority.

Machine-readable custody is in
[`package-qualification.v1.json`](package-qualification.v1.json), closed by
[`package-qualification.v1.schema.json`](package-qualification.v1.schema.json)
and exercised by [`test_package_qualification.py`](test_package_qualification.py).

Observed locally before freeze:

- accepted owner gate: 7 owner cases plus 3 functional CLI cases passed;
- archive qualification: exact archive/inventory/control/interface and
  deterministic reconstruction passed;
- live package installation, VM execution, D-Bus mechanics, and NQ-ng
  integration: **NOT_RUN**.

The rejected owner checkpoint `20cca23bfe2b9bc92c9165c00a498e6db8f890b1`
remains rejected. Qualification attaches to the exact accepted owner subject
and this package child; it does not transfer from the earlier M1A3 archive.
