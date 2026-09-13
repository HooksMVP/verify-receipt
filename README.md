# verify-receipt

Independent, offline verifier for a signed [Chokepoint](https://github.com/HooksMVP/webhooks_service)
Flight Recorder receipt (`chokepoint.flight-recorder/v1`). A GitHub Action
and a GitLab CI template around one Python file — no Chokepoint account,
no network calls to Chokepoint, no secrets. You bring the receipt, a signed
trust-root directory, and its pinned fingerprint; this checks the signature,
the event digests, and the integrity root, and prints what the packet's own
evidence actually supports.

This is a second, independent implementation of the same check the Go
binary in the main repository performs. A verifier that only exists as one
implementation, maintained by the same team that signs the receipts, isn't
independent verification — it's a formality. This repository is deliberately
a separate codebase from Chokepoint's Go CLI, so a bug in one is unlikely to
be a bug in both.

## Usage

### GitHub Actions

```yaml
permissions:
  contents: read
steps:
  - uses: HooksMVP/verify-receipt@v1
    with:
      packet: receipt.json
      trust-root: keys.json
      root-fingerprint: sha256:...
```

A branch-protection check normally gates on this step's exit code alone —
`result == 'complete'` is the only value that passes with every `allow-*`
input at its `"false"` default. It does not need to inspect `result` itself
unless it wants to distinguish *why* a receipt failed.

### GitLab CI

```yaml
include:
  - remote: https://raw.githubusercontent.com/HooksMVP/verify-receipt/v1/gitlab-ci.yml
    inputs:
      packet: receipt.json
      trust_root: keys.json
      root_fingerprint: sha256:...
```

### Local

```sh
python3 -m pip install 'cryptography>=42'
python3 verify_receipt.py \
  --packet receipt.json --trust-root keys.json --root-fingerprint sha256:...
```

## Inputs

| Name | Required | Meaning |
|---|---|---|
| `packet` | yes | Receipt JSON path |
| `trust-root` | yes | Signed `keys.json` directory |
| `root-fingerprint` | yes | `sha256:` pin of the offline root public key |
| `previous-packet` | no | A predecessor receipt, to verify a revision chain |
| `allow-incomplete` | no | Default `false`. Only a verified `evidence_incomplete` receipt may be treated as neutral. Invalid, stale, and untrusted-key still fail. |
| `allow-unevaluated` | no | Default `false`. Only a verified `coverage-unevaluated` receipt may be treated as neutral. |

## Outputs

`result` is one of `complete`, `coverage-unevaluated`, `incomplete`,
`stale`, `invalid`, `untrusted-key`.

**`coverage-unevaluated` means the receipt is authentic and its own claim
is complete, but it is bound to a code change with no record of whether
every commit in that change was observed — it says nothing about the
change's other commits.** Treat it as weaker than `complete`, not as a
failed verification: the signature is genuine, the scope of what it proves
is what's narrower.

Invalid JSON, a one-byte tamper, a stale-evidence gap, or a signer the
trust-root directory doesn't vouch for all fail closed as `invalid` or
`untrusted-key`. Completeness is never implied by the absence of an error.

## Fixtures

[`fixtures/`](fixtures/) holds deterministic, publicly-seeded receipts —
never a production signing key — covering each `result` value:
`receipt.complete.json`, `receipt.incomplete.json`, `receipt.degraded.json`,
`receipt.unevaluated.json`, `receipt.tampered.json`. [`.github/workflows/verify.yml`](.github/workflows/verify.yml)
runs this repository's own Action against every one of them on every push,
asserting the expected result — the same fixtures a `git clone` of this
repository can replay independently of both Chokepoint and GitHub Actions.

## Verifying this repository's own releases

Every tagged release is signed with [Sigstore cosign](https://github.com/sigstore/cosign)
using GitHub Actions' keyless OIDC signing — no private key exists to leak,
rotate, or be handed to you to trust. The signature is published to the
public [Rekor transparency log](https://docs.sigstore.dev/logging/overview/),
independently of this repository and independently of Chokepoint:

```sh
cosign verify-blob \
  --bundle action.yml.cosign.bundle \
  --certificate-identity-regexp "^https://github.com/HooksMVP/verify-receipt/" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  action.yml
```

If that command doesn't pass, don't trust the file — verify the artifact
you're pinning to, not just the tag name.

## What this does not check

A valid signature proves the signer produced this exact metadata and hash
set; it does not prove the underlying change is safe, that GitHub or GitLab
was uncompromised, or that every commit in a change-bound receipt was
observed unless `commit_coverage` says so explicitly. Read the `result`
value for what it actually asserts, not what a green check mark implies.
