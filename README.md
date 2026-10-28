# checksum-claim-audit

Offline auditor for documented digest-computation promises in Python projects.

A README that promises digest checking while the code never computes one
fails only on the first user who installs a corrupted or tampered file
believing it was checked. The reverse is also a broken promise: docs that
promise unchecked passthrough while the code hashes behind the scenes
surprise the first user who counted on that passthrough. This tool checks
the promise against the source, statically, without running anything and
without network access.

## Install

```sh
pip install checksum-claim-audit
checksum-claim-audit /path/to/project
```

Or, without installing:

```sh
python3 -m checksum_claim_audit /path/to/project
```

Requires Python 3.9 or later. Standard library only.

## Usage

```sh
checksum-claim-audit /path/to/project [--json] [--verbose]
    [--ignore 'tests/*'] [--fail-on HIGH|MEDIUM]
checksum-claim-audit --version
```

Exit codes: `0` PASS, `2` FAIL, `1` usage error. With `--json` the
report is machine-readable JSON with `status`, `findings` (rule, severity,
family, evidence), `verified_claims`, and `claims`. With `--fail-on HIGH`,
MEDIUM-only results exit `0`.

Claims are read from the root `README.md` plus `docs/**/*.md` prose.
Fenced code blocks are excluded; inline code counts as prose. Production
source is `*.py` under the root, excluding `tests/`, `fixtures/`, `docs/`,
and `examples/` trees and `test_*.py` / `*_test.py` files. Evidence found
only under tests or fixtures is reported as a MEDIUM test-only finding,
never as production evidence. Symlinked files are skipped. `.env` files
are never opened.

## Rules

One finding per family at most. A family with no production source at all
yields a HIGH finding with evidence `no-source`.

| Rule | Severity | Meaning |
| ---- | -------- | ------- |
| `documented-checksum-claim-false` | HIGH | Positive digest promise, zero production digest evidence |
| `documented-checksum-claim-false-test-only` | MEDIUM | Same, evidence only under tests/fixtures |
| `documented-no-verification-claim-false` | HIGH | Unchecked-passthrough promise, production digest evidence present |
| `documented-no-verification-claim-false-test-only` | MEDIUM | Same, evidence only under tests/fixtures |

Digest evidence is an AST-level call: `hashlib` digest functions,
`hashlib.new`, `hashlib.file_digest`, `hmac.digest`, and
`hmac.compare_digest`, including bare or aliased names imported from
those modules and chained `.hexdigest()` / `.digest()` calls. A bare
`import hashlib` with no digest call is not evidence. The `hash()` builtin
and CRC functions (`zlib.crc32`, `binascii.crc32`) are not evidence.

## Claim phrases

The matcher uses exact phrases only (no optional-middle-word patterns).
The full phrase lists live in this fenced block so the tool does not flag
its own documentation:

```
positive family:
verifies checksums, checksum verification, checksums are verified,
checksum verified, checksum checked, verifies file integrity,
file integrity verified, integrity verified, verifies integrity,
integrity checked, hash verified, verifies hashes,
sha 256 verified, verifies sha 256, sha256 verified, verifies sha256

negative family:
no checksum verification, does not verify checksums,
never verifies checksums, without checksum verification,
no integrity verification, does not verify integrity,
checksums are not verified
```

Negation asymmetry: a sentence containing `no`, `not`, `never`, or
`without` suppresses the positive family only. The negative family is
itself negation phrasing, so it still counts (for example, a sentence
built from the negative list is a negative claim, not a suppressed
positive one). A bare `checksum` noun is not a claim.

## Differentiation

- security-claim-audit audits execution safety (eval, shell, pickle),
  never digest computation.
- auth-claim-audit audits credential requirements, never digest computation.
- format-claim-audit, schema-claim-audit, and config-claim-audit audit
  formats, field names, and default values, never digest behaviour.
- bandit and ruff report code issues, never docs promises.
- `hashlib` documentation and hash-checking install modes describe
  runtime checking, never docs-versus-code truth.

## Honest limitations

- Phrase matching is exact, not semantic: reworded promises outside the
  lists above are missed, and a sentence that mentions a phrase in a
  different sense can be misread.
- Dead code counts: an unreachable digest call still counts as evidence.
- Computing a digest is not proof it is compared against an expected
  value; the tool checks that digest computation exists, not that the
  comparison is correct.
- CRC-style checksums are out of scope; only hashlib/hmac digests count.
- A bare `import hashlib` with no call never counts, and dynamic digest
  selection through `hashlib.new` counts without identifying the algorithm.
- Locally defined functions that shadow an imported digest name are
  excluded; module-level aliasing beyond one import step is not tracked.

## Development

```sh
python3 -m unittest discover -s tests -v
```
