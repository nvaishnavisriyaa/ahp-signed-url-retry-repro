#!/usr/bin/env python3
"""Black-box reproduction of the AHP v1 signed-url / idempotency interaction.

This driver plays the AHP *sender*. It talks to a receiver only over HTTP at a
URL given on the command line; it never imports receiver code. It hosts its own
resource server, because in AHP the sender is the party that hosts the
resources the receiver fetches.

Each case reports: initial state, the injected failure, the HTTP outcome, and
the receiver's resulting stored state. Stored state is read from the receiver's
test-only `/_inspect/state` endpoint, because AHP invariants such as "at most
one set of side effects" and "a failed handoff MUST NOT leave a successful
idempotency result" cannot be observed from the handoff response alone.

Usage:
    python run_cases.py --receiver-digest http://127.0.0.1:8801 \
                        --receiver-legacy http://127.0.0.1:8802
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SIGNING_SECRET = b"alpha-resource-signing-secret"
BEARER = "beta-token-issued-to-alpha"
CLIENT_ID = "alpha-agent"

# The fixture from the AHP examples document, section 5: the inline_blob
# payload "RXhoaWJpdCBBCg==" decodes to these bytes.
FIXTURE = b"Exhibit A\n"
MUTATED = b"Exhibit B\n"


# --------------------------------------------------------------------------
# Sender-side resource host
# --------------------------------------------------------------------------

class ResourceHost:
    """Serves resources behind signed, revocable URLs.

    `rotate()` models a signed url expiring: every previously issued url for
    that document stops working, and a freshly signed one is required.
    """

    def __init__(self):
        self.docs = {"doc-1": FIXTURE}
        self.versions = {"doc-1": 1}
        self.origin = None
        self.serve_count = 0
        self.redirect_target = None

    def _signature(self, doc, version):
        message = f"{doc}|{version}".encode("utf-8")
        return hmac.new(SIGNING_SECRET, message, hashlib.sha256).hexdigest()[:32]

    def sign(self, doc):
        version = self.versions[doc]
        query = urllib.parse.urlencode({
            "doc": doc, "v": version, "sig": self._signature(doc, version),
        })
        return f"{self.origin}/resource?{query}"

    def rotate(self, doc):
        self.versions[doc] += 1

    def set_content(self, doc, payload):
        self.docs[doc] = payload

    def resolve(self, query_string):
        params = urllib.parse.parse_qs(query_string)
        doc = params.get("doc", [""])[0]
        version = params.get("v", [""])[0]
        signature = params.get("sig", [""])[0]
        if doc not in self.docs:
            return 404, b"no such document"
        if not version.isdigit() or int(version) != self.versions[doc]:
            return 403, b"signed url has expired"
        if not hmac.compare_digest(signature, self._signature(doc, int(version))):
            return 403, b"bad signature"
        self.serve_count += 1
        return 200, self.docs[doc]


def start_resource_host(host, port):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/redirect":
                # An allowlisted origin that bounces the receiver elsewhere.
                self.send_response(302)
                self.send_header("Location", host.redirect_target)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if parsed.path != "/resource":
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            status, payload = host.resolve(parsed.query)
            self.send_response(status)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    host.origin = f"http://127.0.0.1:{server.server_address[1]}"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class TrapHost:
    """A disallowed origin. Counts any request that reaches it."""

    def __init__(self):
        self.origin = None
        self.hits = 0


def start_trap_host(trap, port):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_GET(self):
            trap.hits += 1
            payload = b"bytes from a disallowed origin"
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    trap.origin = f"http://127.0.0.1:{server.server_address[1]}"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


# --------------------------------------------------------------------------
# Sender
# --------------------------------------------------------------------------

def digest_of(payload):
    encoded = base64.b64encode(hashlib.sha256(payload).digest()).decode("ascii")
    return f"sha-256=:{encoded}:"


class Sender:
    def __init__(self, host, receiver_url, digest_identity_agreed):
        self.host = host
        self.receiver_url = receiver_url.rstrip("/")
        # Established out of band, before the first digest-dependent transfer.
        self.digest_identity_agreed = digest_identity_agreed

    def package(self, url, declared_digest):
        representation = {"type": "remote", "mime_type": "text/plain", "url": url}
        if declared_digest is not None:
            representation["digest"] = declared_digest
        return {"context": {
            "objective": "Compare the termination provisions and explain the differences.",
            "conversation": [],
            "resources": [{
                "name": "exhibit-a.txt",
                "description": "Fixture from the AHP examples document, section 5.",
                "text": representation,
            }],
        }}

    def post(self, thread_id, key, package):
        request = urllib.request.Request(
            f"{self.receiver_url}/api/ahp/v1/handoffs",
            data=json.dumps(package).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Bearer {BEARER}",
                "Content-Type": "application/json",
                "Accept": "application/json, application/problem+json",
                "Handoff-Thread-Id": thread_id,
                "Handoff-Client-Id": CLIENT_ID,
                "Handoff-Client-Origin": self.host.origin,
                "Idempotency-Key": key,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def retry_with_rotated_url(self, thread_id, key, doc):
        """Retry an uncertain transfer after the original signed url expired.

        Rotating the url changes the request body. A sender may only rely on
        that being a semantically unchanged retry when digest identity has been
        agreed for this integration; otherwise the receiver's fingerprint
        covers the url and the retry is a different logical request.
        """
        if not self.digest_identity_agreed:
            raise RuntimeError(
                "refusing to rotate a resource url on retry: digest identity "
                "is not agreed for this receiver, so the rotated request would "
                "not be recognised as the same transfer"
            )
        fresh = self.host.sign(doc)
        return self.post(thread_id, key, self.package(fresh, digest_of(self.host.docs[doc])))

    def inspect(self):
        with urllib.request.urlopen(f"{self.receiver_url}/_inspect/state", timeout=10) as r:
            return json.loads(r.read())

    def reset(self):
        request = urllib.request.Request(
            f"{self.receiver_url}/_inspect/reset", data=b"", method="POST")
        urllib.request.urlopen(request, timeout=10).read()


# --------------------------------------------------------------------------
# Cases
# --------------------------------------------------------------------------

RESULTS = []


def record(name, passed, expectation, observed):
    RESULTS.append((name, passed, expectation, observed))
    status = "PASS" if passed else "FAIL"
    print(f"[{status}] {name}")
    print(f"       expected: {expectation}")
    print(f"       observed: {observed}")


def case_committed_recovery(host, receiver_url):
    """Committed branch, digest identity agreed.

    Commit the transfer, lose the response, expire the original url, retry with
    a replacement url and an unchanged digest.
    """
    sender = Sender(host, receiver_url, digest_identity_agreed=True)
    sender.reset()
    host.set_content("doc-1", FIXTURE)
    thread_id, key = str(uuid.uuid4()), str(uuid.uuid4())

    url1 = host.sign("doc-1")
    status, body = sender.post(thread_id, key, sender.package(url1, digest_of(FIXTURE)))
    committed = body.get("redirect_url")
    after_first = sender.inspect()

    host.rotate("doc-1")  # the original signed url expires
    status2, body2 = sender.retry_with_rotated_url(thread_id, key, "doc-1")
    after_retry = sender.inspect()

    passed = (
        status == 200 and status2 == 200
        and body2.get("redirect_url") == committed
        and after_retry["threads"] == 1
        and after_retry["idempotency_records"] == 1
        and after_retry["agent_runs"] == 1
        and after_retry["fetches"] == after_first["fetches"] == 1
    )
    record(
        "committed branch recovers (digest identity agreed)",
        passed,
        "retry returns the original continuation; 1 thread, 1 idempotency "
        "record, 1 agent run, no second fetch",
        f"first={status}, retry={status2}, "
        f"same_continuation={body2.get('redirect_url') == committed}, "
        f"threads={after_retry['threads']}, "
        f"idempotency={after_retry['idempotency_records']}, "
        f"agent_runs={after_retry['agent_runs']}, "
        f"fetches={after_retry['fetches']}",
    )


def case_committed_recovery_legacy(host, receiver_url):
    """The same sequence against a receiver that has not adopted the extension."""
    sender = Sender(host, receiver_url, digest_identity_agreed=True)
    sender.reset()
    host.set_content("doc-1", FIXTURE)
    thread_id, key = str(uuid.uuid4()), str(uuid.uuid4())

    url1 = host.sign("doc-1")
    status, body = sender.post(thread_id, key, sender.package(url1, digest_of(FIXTURE)))
    committed = body.get("redirect_url")

    host.rotate("doc-1")
    status2, body2 = sender.retry_with_rotated_url(thread_id, key, "doc-1")
    after = sender.inspect()

    passed = (
        status == 200 and status2 == 409
        and "redirect_url" not in body2
        and after["threads"] == 1
    )
    record(
        "committed branch: a re-signed retry is rejected (url identity)",
        passed,
        "the rotated retry is rejected 409 and that response carries no "
        "continuation url -- see the next case for whether it is recoverable",
        f"first={status}, retry={status2}, "
        f"continuation_returned_by_409={'redirect_url' in body2}, "
        f"committed_continuation_exists={committed is not None and after['threads'] == 1}",
    )


def case_committed_unchanged_retry(host, receiver_url):
    """CONTROL: is the continuation actually unreachable after a 409?

    Commit, lose the response, expire the url, retry with a replacement url
    (baseline 409), then retry with the ORIGINAL unchanged request. If the
    stored result comes back without a second fetch, the continuation was never
    unreachable -- a sender that retained the original body can recover without
    any protocol change.
    """
    sender = Sender(host, receiver_url, digest_identity_agreed=True)
    sender.reset()
    host.set_content("doc-1", FIXTURE)
    thread_id, key = str(uuid.uuid4()), str(uuid.uuid4())

    url1 = host.sign("doc-1")
    original = sender.package(url1, digest_of(FIXTURE))
    status, body = sender.post(thread_id, key, original)
    committed = body.get("redirect_url")

    host.rotate("doc-1")
    status_rotated, _ = sender.retry_with_rotated_url(thread_id, key, "doc-1")

    # Now resend the original body verbatim, expired url and all.
    status_unchanged, body_unchanged = sender.post(thread_id, key, original)
    after = sender.inspect()

    recovered = body_unchanged.get("redirect_url") == committed
    passed = (
        status == 200 and status_rotated == 409
        and status_unchanged == 200 and recovered
        and after["fetches"] == 1 and after["threads"] == 1
    )
    record(
        "CONTROL: unchanged retry recovers the continuation after a 409",
        passed,
        "resending the original body returns the stored result and url with "
        "no second fetch, so the 409 does not make the continuation unreachable",
        f"first={status}, rotated_retry={status_rotated}, "
        f"unchanged_retry={status_unchanged}, same_url={recovered}, "
        f"fetches={after['fetches']}, threads={after['threads']}",
    )


def case_no_record_skips_fingerprint(host, receiver_url):
    """CONTROL: with no stored record, the fingerprint is never consulted.

    §11.3 compares a fingerprint only against a stored prior result. Where no
    successful record exists, a changed body under the same key is processed as
    a fresh transfer and nothing detects the change.

    This does NOT establish that rotating a url is a conforming retry under
    §11.1, that every receiver behaves this way, or that concurrency protection
    is affected -- the same-key lock still serialises these requests. It shows
    only that this receiver had no stored successful result to compare against,
    so the changed body was not detected.

    The sender here knows it is in the uncommitted branch only because the test
    constructed it that way. A real sender cannot infer that from a 502, which
    an intermediary may return after the application committed.
    """
    sender = Sender(host, receiver_url, digest_identity_agreed=True)
    sender.reset()
    host.set_content("doc-1", FIXTURE)
    thread_id, key = str(uuid.uuid4()), str(uuid.uuid4())

    url1 = host.sign("doc-1")
    host.rotate("doc-1")                       # expires before first fetch
    original = sender.package(url1, digest_of(FIXTURE))

    first, _ = sender.post(thread_id, key, original)        # 502
    unchanged, _ = sender.post(thread_id, key, original)    # 502 again
    after_failures = sender.inspect()
    resigned, body = sender.retry_with_rotated_url(thread_id, key, "doc-1")
    after = sender.inspect()

    passed = (
        first == 502 and unchanged == 502
        and after_failures["idempotency_records"] == 0
        and resigned == 200 and body.get("redirect_url")
        and after["threads"] == 1 and after["idempotency_records"] == 1
    )
    record(
        "CONTROL: changed body under the same key passes unchecked when no "
        "record exists",
        passed,
        "this receiver had no stored successful result to compare against, so "
        "the changed body was not detected -- this does not establish that "
        "rotation is a conforming retry, nor how other receivers behave",
        f"first={first}, unchanged_retry={unchanged}, "
        f"records_after_failures={after_failures['idempotency_records']}, "
        f"same_key_changed_body={resigned}, threads={after['threads']}, "
        f"idempotency={after['idempotency_records']}",
    )


def case_redirect_rejected(host, trap, receiver_url):
    """A redirect from an allowlisted origin to a disallowed one."""
    sender = Sender(host, receiver_url, digest_identity_agreed=True)
    sender.reset()
    host.redirect_target = f"{trap.origin}/stolen"
    before_hits = trap.hits
    thread_id, key = str(uuid.uuid4()), str(uuid.uuid4())

    status, body = sender.post(thread_id, key, sender.package(
        f"{host.origin}/redirect", digest_of(FIXTURE)))
    after = sender.inspect()

    passed = (
        status == 502
        and trap.hits == before_hits
        and after["threads"] == 0
        and after["idempotency_records"] == 0
        and after["materialised_resources"] == 0
    )
    record(
        "redirect to a disallowed origin is refused before any request",
        passed,
        "handoff rejected, the disallowed target receives no request at all, "
        "and nothing is committed",
        f"status={status}, type={body.get('title')}, "
        f"disallowed_target_hits={trap.hits - before_hits}, "
        f"threads={after['threads']}, "
        f"idempotency={after['idempotency_records']}",
    )


def case_uncommitted_recovery(host, receiver_url):
    """Uncommitted branch: the first attempt never commits, then recovers."""
    sender = Sender(host, receiver_url, digest_identity_agreed=True)
    sender.reset()
    host.set_content("doc-1", FIXTURE)
    thread_id, key = str(uuid.uuid4()), str(uuid.uuid4())

    url1 = host.sign("doc-1")
    host.rotate("doc-1")  # url expires before the receiver can fetch it
    status, _ = sender.post(thread_id, key, sender.package(url1, digest_of(FIXTURE)))
    after_failure = sender.inspect()

    status2, body2 = sender.retry_with_rotated_url(thread_id, key, "doc-1")
    after_retry = sender.inspect()

    passed = (
        status == 502
        and after_failure["threads"] == 0
        and after_failure["idempotency_records"] == 0
        and after_failure["materialised_resources"] == 0
        and status2 == 200
        and after_retry["threads"] == 1
        and after_retry["idempotency_records"] == 1
        and after_retry["materialised_resources"] == 1
    )
    record(
        "uncommitted branch recovers with exactly one continuation",
        passed,
        "first attempt fails 502 leaving no stored state; retry creates "
        "exactly one verified continuation",
        f"first={status}, state_after_failure=threads={after_failure['threads']}/"
        f"idempotency={after_failure['idempotency_records']}/"
        f"materialised={after_failure['materialised_resources']}, "
        f"retry={status2}, threads={after_retry['threads']}, "
        f"materialised={after_retry['materialised_resources']}",
    )


def case_mismatch_rollback(host, receiver_url):
    """Declared digest does not match the bytes the url serves."""
    sender = Sender(host, receiver_url, digest_identity_agreed=True)
    sender.reset()
    thread_id, key = str(uuid.uuid4()), str(uuid.uuid4())

    host.set_content("doc-1", MUTATED)        # url now serves different bytes
    url = host.sign("doc-1")
    status, body = sender.post(
        thread_id, key, sender.package(url, digest_of(FIXTURE)))  # stale digest
    after = sender.inspect()

    passed = (
        status == 502
        and after["threads"] == 0
        and after["idempotency_records"] == 0
        and after["materialised_resources"] == 0
        and after["agent_runs"] == 0
    )
    record(
        "digest mismatch is rejected and rolled back",
        passed,
        "handoff rejected; no thread, no idempotency record, no retained bytes",
        f"status={status}, type={body.get('title')}, threads={after['threads']}, "
        f"idempotency={after['idempotency_records']}, "
        f"materialised={after['materialised_resources']}, "
        f"agent_runs={after['agent_runs']}",
    )


def case_mismatch_silent_legacy(host, receiver_url):
    """The same mismatch against a receiver that ignores the digest member."""
    sender = Sender(host, receiver_url, digest_identity_agreed=True)
    sender.reset()
    thread_id, key = str(uuid.uuid4()), str(uuid.uuid4())

    host.set_content("doc-1", MUTATED)
    url = host.sign("doc-1")
    status, _ = sender.post(thread_id, key, sender.package(url, digest_of(FIXTURE)))
    after = sender.inspect()

    passed = status == 200 and after["threads"] == 1
    record(
        "url-identity receiver accepts mismatched bytes silently",
        passed,
        "200 and a committed continuation built from bytes the sender never "
        "declared, so a success response does not establish extension support",
        f"status={status}, threads={after['threads']}, "
        f"materialised={after['materialised_resources']}",
    )


def case_sender_guard(host, receiver_url):
    """A sender without agreed digest identity must refuse to rotate a url."""
    sender = Sender(host, receiver_url, digest_identity_agreed=False)
    sender.reset()
    thread_id, key = str(uuid.uuid4()), str(uuid.uuid4())

    url1 = host.sign("doc-1")
    sender.post(thread_id, key, sender.package(url1, None))
    host.rotate("doc-1")

    refused, message = False, ""
    try:
        sender.retry_with_rotated_url(thread_id, key, "doc-1")
    except RuntimeError as exc:
        refused, message = True, str(exc)

    record(
        "sender refuses digest identity without agreed support",
        refused,
        "the sender aborts rather than rotating the url, because support must "
        "be established before the first digest-dependent transfer",
        f"refused={refused}: {message[:70]}" if refused else "sender rotated anyway",
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--receiver-digest", required=True)
    parser.add_argument("--receiver-legacy", required=True)
    parser.add_argument("--resource-port", type=int, default=8899)
    parser.add_argument("--trap-port", type=int, default=8898)
    args = parser.parse_args()

    host = ResourceHost()
    start_resource_host(host, args.resource_port)
    trap = TrapHost()
    start_trap_host(trap, args.trap_port)
    print(f"sender resource host: {host.origin}")
    print(f"disallowed trap origin: {trap.origin}\n")

    print("--- receiver with digest identity agreed ---")
    case_committed_recovery(host, args.receiver_digest)
    case_uncommitted_recovery(host, args.receiver_digest)
    case_mismatch_rollback(host, args.receiver_digest)
    case_redirect_rejected(host, trap, args.receiver_digest)

    print("\n--- baseline receiver using url identity ---")
    case_committed_recovery_legacy(host, args.receiver_legacy)
    case_committed_unchanged_retry(host, args.receiver_legacy)
    case_no_record_skips_fingerprint(host, args.receiver_legacy)
    case_mismatch_silent_legacy(host, args.receiver_legacy)
    case_sender_guard(host, args.receiver_legacy)

    failures = [name for name, passed, _, _ in RESULTS if not passed]
    print(f"\n{len(RESULTS) - len(failures)}/{len(RESULTS)} cases behaved as described")
    if failures:
        for name in failures:
            print(f"  unexpected: {name}")
        sys.exit(1)


if __name__ == "__main__":
    main()
