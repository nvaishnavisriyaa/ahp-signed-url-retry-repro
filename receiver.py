#!/usr/bin/env python3
"""A minimal AHP v1 receiver, used as the system under test for the
digest-identity reproduction.

SCOPE AND ASSUMPTIONS
---------------------
This is a demonstration receiver, not a conforming production implementation.
It implements only what the reproduction needs to make the recovery branches
observable:

  * discovery (`/.well-known/agent-handoff-spec.json`)
  * one authenticated handoff POST
  * scoped, lock-serialised idempotency with request fingerprinting
  * remote resource materialisation with an origin allowlist, size cap and
    timeout
  * atomic commit of thread + idempotency record

It deliberately does NOT implement: OAuth, tenant provisioning, redirect
following with re-validation, decompression-ratio limits, malware scanning,
rate limiting, audit logging, persistence across restarts, or the
`durable authorized reference` alternative to materialisation. State is
in-memory and is lost on exit.

IDENTITY MODE
-------------
`--identity-mode url` models a receiver that has NOT adopted the proposed
digest extension. Per AHP v1 section 5.2 it ignores the unrecognised
`digest` member, and its request fingerprint therefore covers the resource
`url` verbatim. It performs no integrity check.

`--identity-mode digest` models a receiver for which digest identity has been
agreed bilaterally. When a remote representation carries a `digest`:
  * the fingerprint covers the digest in place of the url;
  * the fetched bytes MUST hash to that digest or the whole handoff fails;
  * the representation MUST be materialised and the verified bytes retained.

TEST-ONLY SURFACE
-----------------
`/_inspect/state` and `/_inspect/reset` are NOT part of AHP. They exist
because several AHP v1 invariants -- "at most one set of side effects",
"a failed handoff MUST NOT leave a successful idempotency result" -- are not
observable from the handoff response alone.
"""

import argparse
import base64
import hashlib
import json
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_RESOURCE_BYTES = 8 * 1024 * 1024
FETCH_TIMEOUT_SECONDS = 10

# Bilaterally configured out of band, per AHP v1 section 6.
CONFIG = {
    "bearer_token": "beta-token-issued-to-alpha",
    "client_id": "alpha-agent",
    "tenant": "beta-tenant-1",
    "user": "user-42",
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect.

    urllib's default opener follows redirects, so checking only the initial
    origin would leave an allowlisted origin able to bounce the receiver to a
    disallowed one. Section 8.6 requires resolving and re-checking every
    redirect target; this prototype takes the stricter and simpler option of
    rejecting redirects outright. Validating the final url after the fetch
    would be too late -- the request to the disallowed target has already
    happened.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


class ProblemDetail(Exception):
    """An error carrying the HTTP status the receiver should return."""

    def __init__(self, status, slug, detail):
        super().__init__(detail)
        self.status = status
        self.slug = slug
        self.detail = detail


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def parse_digest(raw):
    """Parse the RFC 9530-style serialisation `sha-256=:<base64>:`.

    AHP would need to pin this syntax narrowly; this accepts sha-256 only and
    rejects anything whose decoded length is not 32 bytes.
    """
    if not isinstance(raw, str) or not raw.startswith("sha-256=:") or not raw.endswith(":"):
        raise ProblemDetail(422, "malformed-digest", "digest must be sha-256=:<base64>:")
    encoded = raw[len("sha-256=:"):-1]
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except Exception:
        raise ProblemDetail(422, "malformed-digest", "digest is not valid base64")
    if len(decoded) != 32:
        raise ProblemDetail(
            422, "malformed-digest",
            f"sha-256 digest must decode to 32 bytes, got {len(decoded)}",
        )
    return decoded


class ReceiverState:
    """In-memory durable store. Writes happen only inside commit()."""

    def __init__(self):
        self.lock = threading.Lock()
        self.key_locks = defaultdict(threading.Lock)
        self.threads = {}        # thread scope -> record
        self.idempotency = {}    # key scope -> {fingerprint, response}
        self.materialised = []   # retained verified bytes (metadata only)
        self.fetch_log = []      # every outbound GET the receiver performed
        self.agent_runs = []     # one entry per scheduled continuation

    def reset(self):
        with self.lock:
            self.threads.clear()
            self.idempotency.clear()
            self.materialised.clear()
            self.fetch_log.clear()
            self.agent_runs.clear()
            self.key_locks.clear()

    def snapshot(self):
        with self.lock:
            return {
                "threads": len(self.threads),
                "idempotency_records": len(self.idempotency),
                "materialised_resources": len(self.materialised),
                "fetches": len(self.fetch_log),
                "fetch_log": list(self.fetch_log),
                "agent_runs": len(self.agent_runs),
                "continuations": sorted(
                    r["redirect_url"] for r in self.threads.values()
                ),
            }


class Receiver:
    def __init__(self, identity_mode, public_base, resource_origins):
        self.identity_mode = identity_mode
        self.public_base = public_base.rstrip("/")
        self.resource_origins = set(resource_origins)
        self.state = ReceiverState()

    # -- section 6: authentication and client binding --------------------

    def authenticate(self, headers):
        auth = headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise ProblemDetail(401, "unauthenticated", "missing bearer credential")
        if auth[len("Bearer "):] != CONFIG["bearer_token"]:
            raise ProblemDetail(401, "unauthenticated", "invalid bearer credential")
        return {"tenant": CONFIG["tenant"], "user": CONFIG["user"]}

    def bind_client(self, headers):
        client_id = headers.get("Handoff-Client-Id")
        origin = headers.get("Handoff-Client-Origin")
        if client_id != CONFIG["client_id"]:
            raise ProblemDetail(422, "client-assertion-rejected", "unknown client id")
        if origin not in self.resource_origins:
            raise ProblemDetail(422, "client-assertion-rejected", "unconfigured origin")
        return {"client_id": client_id, "origin": origin}

    # -- section 8: request validation -----------------------------------

    def validate_request(self, headers, body):
        thread_id = headers.get("Handoff-Thread-Id")
        if not thread_id or len(thread_id) > 255 or not thread_id.isprintable():
            raise ProblemDetail(400, "invalid-thread-id", "bad Handoff-Thread-Id")
        raw_key = headers.get("Idempotency-Key", "")
        try:
            key = str(uuid.UUID(raw_key))
        except ValueError:
            raise ProblemDetail(400, "invalid-idempotency-key", "key must be a UUID")

        try:
            package = json.loads(body)
        except json.JSONDecodeError:
            raise ProblemDetail(400, "malformed-json", "body is not valid JSON")

        context = package.get("context")
        if not isinstance(context, dict):
            raise ProblemDetail(422, "schema-violation", "context is required")
        objective = context.get("objective")
        if not isinstance(objective, str) or not objective.strip():
            raise ProblemDetail(422, "schema-violation", "objective must be non-empty")
        for field in ("conversation", "resources"):
            if not isinstance(context.get(field), list):
                raise ProblemDetail(422, "schema-violation", f"{field} must be an array")
        for resource in context["resources"]:
            if not isinstance(resource.get("name"), str) or not resource["name"]:
                raise ProblemDetail(422, "schema-violation", "resource name required")
            if resource.get("blob") is None and resource.get("text") is None:
                raise ProblemDetail(422, "schema-violation", "resource needs blob or text")

        return thread_id, key, package

    # -- section 11.3: request fingerprint --------------------------------

    def fingerprint(self, target, client, thread_id, package):
        """Identity of the logical request.

        In `url` mode the resource url is part of identity, so re-signing a
        url changes identity. In `digest` mode a representation that carries a
        digest contributes that digest instead, so a credential-bearing url may
        rotate freely while content identity stays fixed. Query parameters that
        select different content still change the bytes, and therefore still
        change the digest.
        """
        identity_package = json.loads(json.dumps(package))
        if self.identity_mode == "digest":
            for resource in identity_package.get("context", {}).get("resources", []):
                for slot in ("blob", "text"):
                    rep = resource.get(slot)
                    if isinstance(rep, dict) and rep.get("type") == "remote":
                        if isinstance(rep.get("digest"), str):
                            parse_digest(rep["digest"])
                            rep.pop("url", None)
        material = canonical_json({
            "version": "v1",
            "target": target,
            "client": client,
            "thread_id": thread_id,
            "package": identity_package,
        })
        return hashlib.sha256(material).hexdigest()

    # -- section 8.6: remote content --------------------------------------

    def fetch_remote(self, url, expected_digest):
        parsed = urllib.parse.urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin not in self.resource_origins:
            raise ProblemDetail(422, "resource-origin-rejected", f"origin {origin} not allowed")

        self.state.fetch_log.append(url)
        request = urllib.request.Request(url, method="GET")
        try:
            with _OPENER.open(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
                payload = response.read(MAX_RESOURCE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                raise ProblemDetail(
                    502, "resource-redirect-rejected",
                    f"refusing to follow a redirect from {origin}",
                )
            raise ProblemDetail(502, "resource-fetch-failed", f"upstream returned {exc.code}")
        except urllib.error.URLError as exc:
            raise ProblemDetail(504, "resource-fetch-failed", f"upstream unreachable: {exc}")
        if len(payload) > MAX_RESOURCE_BYTES:
            raise ProblemDetail(413, "resource-too-large", "representation exceeds cap")

        # Hash the complete representation after HTTP content decoding and
        # before any text decoding, extraction or normalisation.
        if expected_digest is not None:
            actual = hashlib.sha256(payload).digest()
            if actual != expected_digest:
                raise ProblemDetail(
                    502, "resource-digest-mismatch",
                    "fetched bytes do not match the declared digest",
                )
        return payload

    def materialise(self, package):
        """Fetch every remote representation. Returns retained bytes, or raises.

        Nothing reaches durable state from here; the caller commits.
        """
        retained = []
        for resource in package["context"]["resources"]:
            for slot in ("blob", "text"):
                rep = resource.get(slot)
                if not isinstance(rep, dict) or rep.get("type") != "remote":
                    continue
                expected = None
                if self.identity_mode == "digest" and isinstance(rep.get("digest"), str):
                    expected = parse_digest(rep["digest"])
                payload = self.fetch_remote(rep["url"], expected)
                retained.append({
                    "name": resource["name"],
                    "slot": slot,
                    "bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "verified": expected is not None,
                })
        return retained

    # -- section 10: processing model -------------------------------------

    def handle_handoff(self, headers, body):
        target = self.authenticate(headers)
        client = self.bind_client(headers)
        thread_id, key, package = self.validate_request(headers, body)
        fingerprint = self.fingerprint(target, client, thread_id, package)

        scope = (target["tenant"], target["user"], client["client_id"],
                 client["origin"], key)
        thread_scope = (target["tenant"], target["user"], client["client_id"],
                        client["origin"], thread_id)

        with self.state.key_locks[scope]:
            prior = self.state.idempotency.get(scope)
            if prior is not None:
                if prior["fingerprint"] != fingerprint:
                    raise ProblemDetail(
                        409, "idempotency-key-reused",
                        "key belongs to a different handoff request",
                    )
                return prior["response"]

            retained = self.materialise(package)

            with self.state.lock:
                existing = self.state.threads.get(thread_scope)
                if existing is None:
                    redirect = f"{self.public_base}/workspaces/continue/{uuid.uuid4().hex[:8]}"
                    self.state.threads[thread_scope] = {
                        "redirect_url": redirect,
                        "objective": package["context"]["objective"],
                    }
                else:
                    redirect = existing["redirect_url"]
                self.state.materialised.extend(retained)
                response = {"redirect_url": redirect}
                self.state.idempotency[scope] = {
                    "fingerprint": fingerprint,
                    "response": response,
                }
                self.state.agent_runs.append(thread_scope)
            return response


def build_handler(receiver):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def _send(self, status, payload, content_type="application/json"):
            encoded = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self):
            if self.path == "/.well-known/agent-handoff-spec.json":
                self._send(200, {"v1": {
                    "handoff_endpoint_url": f"{receiver.public_base}/api/ahp/v1/handoffs"
                }})
            elif self.path == "/_inspect/state":
                self._send(200, receiver.state.snapshot())
            else:
                self._send(404, {"title": "not found"})

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""
            if self.path == "/_inspect/reset":
                receiver.state.reset()
                self._send(200, {"reset": True})
                return
            if self.path != "/api/ahp/v1/handoffs":
                self._send(404, {"title": "not found"})
                return
            try:
                self._send(200, receiver.handle_handoff(self.headers, body))
            except ProblemDetail as problem:
                self._send(problem.status, {
                    "type": f"urn:example:ahp:{problem.slug}",
                    "title": problem.slug,
                    "status": problem.status,
                    "detail": problem.detail,
                }, content_type="application/problem+json")

    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--identity-mode", choices=["url", "digest"], required=True)
    parser.add_argument("--resource-origin", action="append", default=[])
    args = parser.parse_args()

    base = f"http://127.0.0.1:{args.port}"
    receiver = Receiver(args.identity_mode, base, args.resource_origin)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), build_handler(receiver))
    print(f"receiver[{args.identity_mode}] listening on {base}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
