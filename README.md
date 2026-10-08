# AHP v1 — signed-url retry reproduction

A runnable reproduction of how AHP v1 signed resource urls (§8.6), request
fingerprinting (§11.3) and retry rules (§11.1, §11.5) interact, plus a
demonstration of a proposed optional `digest` extension.

Python 3.8+, standard library only. No dependencies, no external network access.

## Running it

```bash
python demo.py
```

That starts both receivers, runs every case against them, tears them down, and
exits non-zero if any case does not behave as described. Python 3.8+, no
dependencies, no external network access.

**Url expiry is simulated by invalidating the signature, not by waiting.** Each
signed url carries a per-document version that the signature covers; rotating
that version invalidates every url issued earlier. Rotation changes only the
authorisation token — the underlying bytes are untouched — and no case sleeps.

To drive the receivers yourself, or to point the driver at a different receiver:

```bash
python receiver.py --port 8801 --identity-mode digest --resource-origin http://127.0.0.1:8899 &
python receiver.py --port 8802 --identity-mode url    --resource-origin http://127.0.0.1:8899 &

python run_cases.py --receiver-digest http://127.0.0.1:8801 \
                    --receiver-legacy http://127.0.0.1:8802
```

- `--identity-mode url` is the **baseline** demonstration receiver. Per §5.2 it
  ignores the unrecognised `digest` member, and its fingerprint covers the
  resource `url` verbatim. It is not DeepJudge's implementation, and nothing
  here demonstrates a defect in any product.
- `--identity-mode digest` models a receiver for which digest identity has been
  agreed bilaterally, before the first digest-dependent transfer.

## What it found

The reproduction was built to test the hypothesis that an expired signed url
could strand a committed handoff. **That hypothesis is false**, and a control
case disproves it:

> While the successful idempotency record remains retained, resending the
> **original unchanged** request returns the stored result and url without
> re-fetching, even though the signed url in that body has expired.
> `unchanged_retry=200, same_url=True, fetches=1`
>
> The experiment does not resolve how a sender should refresh an expired url
> while commitment remains uncertain.

What that does **not** establish, and an earlier draft of this README wrongly
claimed:

- **A `502` does not prove nothing committed.** Here it comes from the
  receiver's own materialisation step and the driver can inspect its state. A
  real sender cannot: an intermediary may return `502` after the application
  committed. A status code is not permission to modify a request or change keys.
- **The uncommitted-branch case reuses the same key with a rotated url**, which
  assumes the answer to the open question in #1. It succeeded only because no
  stored record existed, so the fingerprint was never compared.
- **Recovery depends on retention.** It holds while the successful idempotency
  record remains retained; §11.4 requires at least 24 hours and recommends
  keeping it as long as the handoff record.

So one branch is recoverable and the ambiguous one remains open. Separately,
nothing in AHP binds approved content to the bytes a receiver fetches.

The two write-ups are split accordingly: [ISSUE1-COMMENT.md](ISSUE1-COMMENT.md)
for the recovery finding, [PROPOSAL-digest.md](PROPOSAL-digest.md) for content
verification.

## Design

The driver talks to a receiver only over HTTP at a url given on the command
line and never imports receiver code. That reduces implementation coupling, but
does not rule out both sides encoding the same mistaken reading of the spec.

Stored state is read from a test-only `/_inspect/state` endpoint, because
invariants such as "at most one set of side effects" and "a failed handoff MUST
NOT leave a successful idempotency result" (§10) are not observable from the
handoff response alone. That endpoint is not part of AHP.

The fixture is from the examples document §5: `RXhoaWJpdCBBCg==` decodes to
`Exhibit A\n`, whose SHA-256 is
`sha-256=:i3A3aFqy3KIVBUhVRPYi7INZMqvxDQmyZhCUmxkBs8s=:`. Reproduce with
`printf 'Exhibit A\n' | openssl dgst -sha256 -binary | openssl base64`.

## Cases

```
--- receiver with digest identity agreed ---
[PASS] committed branch recovers (digest identity agreed)
       first=200, retry=200, same_continuation=True, threads=1,
       idempotency=1, agent_runs=1, fetches=1
[PASS] uncommitted branch recovers with exactly one continuation
       first=502, state_after_failure=threads=0/idempotency=0/materialised=0,
       retry=200, threads=1, materialised=1
[PASS] digest mismatch is rejected and rolled back
       status=502, type=resource-digest-mismatch, threads=0, idempotency=0,
       materialised=0, agent_runs=0
[PASS] redirect to a disallowed origin is refused before any request
       status=502, type=resource-redirect-rejected, disallowed_target_hits=0,
       threads=0, idempotency=0

--- baseline receiver using url identity ---
[PASS] committed branch loses the continuation (url identity)
       first=200, retry=409, continuation_returned=False
[PASS] CONTROL: unchanged retry recovers the continuation after a 409
       first=200, rotated_retry=409, unchanged_retry=200, same_url=True,
       fetches=1, threads=1
[PASS] CONTROL: two-step recovery works on the baseline receiver
       first=502, unchanged_retry=502, records_after_failures=0,
       resigned_retry=200, threads=1, idempotency=1
[PASS] url-identity receiver accepts mismatched bytes silently
       status=200, threads=1, materialised=1
[PASS] sender refuses digest identity without agreed support
       refused=True

9/9 cases behaved as described
```

`PASS` means the case behaved as described, not that the behaviour is desirable.
Three of the nine describe behaviour worth changing or documenting:

- **`409` on a re-signed retry** — correct per §11.3, but the sender must know
  to fall back to the unchanged body. No section says so.
- **mismatched bytes accepted silently** — the baseline receiver never agreed to
  honour `digest`, so this is not a violation. It shows that a `200` does not
  establish extension support, and that support must be configured out of band.
- **`409` is not evidence of commitment** on its own. §12 also uses `409` for
  ownership and return-deployment conflicts. Here commitment is established by
  inspecting stored state, not by the status code.

## Scope and limits

`receiver.py` is a demonstration receiver, not a conforming implementation. It
implements discovery, one authenticated handoff POST, scoped lock-serialised
idempotency, remote materialisation with an origin allowlist, size cap, timeout
and outright redirect rejection, and atomic commit.

It does **not** implement OAuth, tenant provisioning, redirect following with
re-validation (it refuses redirects instead, which is stricter and simpler than
§8.6 requires), decompression-ratio limits, malware scanning, rate limiting,
audit logging, persistence, or the `durable authorized reference` alternative to
materialisation. State is in-memory.

The cases cover this interaction only. They are not a conformance suite and do
not exercise concurrency, round trips, sender-side redirect validation, or the
rest of §16.3.
