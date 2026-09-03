# nks-talk-notify

A minimal, self-hosted push proxy that lets push notifications reach a
**closed** NKS Talk app (`com.nkshub.nextcloudtalk`), the third-party
Nextcloud Talk client this project builds — iOS via APNs, Android via FCM.
Either provider can be configured independently; a deployment with only one
of the two runs fine.

## Why this exists

Nextcloud does not talk to APNs (Apple's push service) directly. Instead the
server signs a notification and forwards it to a "push proxy" URL that the
client chose when it registered
(`apps/notifications/lib/Push.php`, `sendNotificationsToProxies()`, around
line 727: `$client->post($proxyServer . '/notifications', $requestData)`).
Nextcloud's own public proxy, `https://push-notifications.nextcloud.com`,
signs every push with **Nextcloud's own APNs developer key**, scoped to
their app's bundle id `com.nextcloud.talk2`. Apple only delivers a push if
its signing key matches the target app's bundle id, so that public proxy can
never deliver to `com.nkshub.nextcloudtalk` — a different app.

Without a proxy that holds an APNs key for *this* app, iOS notifications
never reach the app while it is closed or suspended (websocket-based
delivery such as `notify_push` only works while the app is running in the
foreground). This service is that proxy: it holds the app's own APNs key and
nothing else — it never decrypts a notification's content, it only routes
already-encrypted, already-signed messages to Apple.

Android's equivalent problem: the app used to route through
`org.unifiedpush.android:embedded-fcm-distributor`, a public UnifiedPush
gateway that re-delivers Web Push requests as FCM messages through Google
Play Services. Content stayed encrypted, but the app depended on
infrastructure this project doesn't control for basic delivery. Android is
Talk's **native** push path now, on the same push-v2 contract as iOS, over
this same proxy — UnifiedPush Web Push remains available as a switchable
fallback in the app if this path ever has problems, but is not the default.
Nextcloud is no more aware of Android's provider than it is of iOS's: same
`Push.php` code path, same `proxyserver` grouping, no platform branching on
the server at all — this proxy is the only thing that knows a given
registered device is an iPhone or an Android phone, and it only knows
because of the *shape* of the token the device handed it (see
`token_kind()` below), not because anyone tells it.

## The wire contract (verified against Nextcloud source)

Everything below was read out of a live Nextcloud 34.0.1 install, not
guessed. File paths and line numbers refer to
`apps/notifications/lib/` in the `notifications` app.

### 1. The client tells Nextcloud which proxy to use

`POST /ocs/v2.php/apps/notifications/api/v2/push` with `pushTokenHash`,
`devicePublicKey`, `proxyServer` — handled by
`Controller/PushController.php::registerDevice()` (line 64). Nextcloud only
validates the URL (must be `https://`, ≤256 chars, resolvable host; `http://
localhost` and `*.internal`/`*.local` are allowed for testing) and stores it
in `oc_notifications_pushhash.proxyserver`. It does **not** call the proxy
during this step.

In the same call, Nextcloud signs a private JSON preimage
`[cloudId, sessionTokenId]` with the user's identity-proof RSA key
(`openssl_sign(..., OPENSSL_ALGO_SHA512)`, line 117), then immediately
overwrites the value it will actually publish: `deviceIdentifier =
base64(sha512(preimage))` (line 123). The proxy therefore only ever sees
that digest — never the preimage.

### 2. The client registers itself with this proxy — `POST /devices`

Not part of the OCS API above; this endpoint is specific to whichever proxy
`proxyServer` points at. This proxy needs it because Nextcloud only ever
gives it `pushTokenHash` (a SHA-512 digest), never the real device token —
so the client must give us the real token directly.

Form-urlencoded body:

| field | meaning |
| --- | --- |
| `pushToken` | the real device token — APNs (hex string) or FCM registration token, see below |
| `pushProvider` | `apns` or `fcm`; current clients always send this explicitly |
| `pushEnvironment` | required for APNs: `development` or `production`; forbidden for FCM |
| `deviceIdentifier` | `base64(sha512(preimage))`, exactly as Nextcloud returned it |
| `deviceIdentifierSignature` | `base64(signature)`, exactly as Nextcloud returned it |
| `userPublicKey` | `publicKey`, exactly as Nextcloud returned it |

**Client contract that is not visible in this repo:** the `pushTokenHash`
the client sends to *Nextcloud* must equal `sha512(pushToken)` computed the
same way this proxy computes it — SHA-512 of the UTF-8 hex token string
(`app/server.py::App.push_token_hash`). If the mobile client hashes
differently (e.g. over raw token bytes instead of the hex string), delivery
lookups in `POST /notifications` will never match. Confirmed with the iOS
and Android registration flows.

See `app/crypto.py` for exactly how the signature is verified and why it
cannot be verified as a normal signature (the digest, not the preimage, is
all the proxy ever has).

Current clients declare `pushProvider=apns|fcm`. This matters because the
documented FCM alphabet includes lowercase hex strings too, so token shape is
not an identity. APNs tokens must be 64-200 lowercase hex characters and carry
`pushEnvironment=development|production`; FCM tokens use the strict
`[A-Za-z0-9_:-]` whitelist at 32-4096 characters and must not carry an APNs
environment. Rows created before `pushProvider` existed keep a null provider;
only those legacy rows use `token_kind()` shape inference during delivery.

Responses: `200` empty body on success (matches what current official
clients expect), `400` on a missing/invalid field or a signature that
doesn't verify, `403` if `deviceIdentifier` is already registered under a
*different* `userPublicKey` (see Security below).

### 3. `DELETE /devices`

Form-urlencoded body only: `deviceIdentifier`,
`deviceIdentifierSignature`. The signature is checked against the **stored**
public key, not one the caller supplies — otherwise anyone could delete any
registration just by presenting a signature over a key of their own choice.
`200` if nothing was registered (idempotent) or on deletion (push-v2 spec —
not `202`), `400` if the signature doesn't verify or either identity field is
put in the query string. Keeping identity out of the request line prevents it
from reaching reverse-proxy and HTTP access logs.

### 4. Nextcloud sends notifications — `POST /notifications`

`Push::sendNotificationsToProxies()` (line 686) posts
`{"body": {"notifications": [...]}}` through Nextcloud's HTTP client, which
turns an array body into `application/x-www-form-urlencoded`
`notifications[0]=<json>&notifications[1]=<json>&...` — **not** a JSON
request body. Each `notifications[N]` value is itself a JSON string built by
`Push::encryptAndSign()` (line 960, or `encryptAndSignDelete()` at line 1006
for a "delete this notification" push) with 6 fields:

```json
{
  "deviceIdentifier": "...",
  "pushTokenHash": "...",
  "subject": "<base64 RSA-encrypted ciphertext, opaque to this proxy>",
  "signature": "<base64 RSA-SHA512 signature over the raw ciphertext bytes>",
  "priority": "high|normal",
  "type": "alert|voip|background"
}
```

`subject` is encrypted with the **device's own public key**
(`devicePublicKey` from step 1, a separate keypair from `userPublicKey`) —
this proxy cannot decrypt it and does not try to. Only the app's
Notification Service Extension, holding the matching device private key,
can. `priority`/`type` come from `Push::getNotifTopicAndUrgency()` (line
935): Talk messages/calls are `high`/`voip` or `high`/`alert`, everything
else defaults to `normal`/`alert`, deletions are always `normal`/`background`.

This proxy verifies `signature` against the **stored** `userPublicKey` for
that `deviceIdentifier` (plain RSA-SHA512 over the decoded ciphertext, see
`crypto.verify_subject_signature`) before ever calling APNs or FCM — this
is the only thing standing between "any HTTP client on the internet" and
pushing arbitrary payloads to a real device, since this endpoint itself has
no other authentication beyond S1's optional subscription key.

**Which provider actually gets called** is the stored `push_provider` —
`app/server.py::App._send_via_apns()` /
`_send_via_fcm()`:

- **APNs** (`app/apns.py`): as described elsewhere in this document —
  `mutable-content: 1` + generic alert, encrypted `subject` in `nc-subject`.
- **FCM** (`app/fcm.py`, HTTP v1): `POST
  https://fcm.googleapis.com/v1/projects/<project-id>/messages:send`,
  authenticated with an OAuth2 access token minted from a Google service
  account JSON (RS256 JWT bearer grant, cached the same way the APNs JWT
  is). The message is **`data`-only** — no `notification` block, or Android
  renders a plaintext OS banner itself and the app never gets a chance to
  decrypt anything, the same reasoning as APNs' `mutable-content`:
  ```json
  {"message": {"token": "<fcm token>", "data": {"nc-subject": "..."}, "android": {"priority": "high"}}}
  ```
  `priority` maps directly (Nextcloud's `high`/`normal` are already FCM's
  `android.priority` values, no translation table needed). FCM v1's error
  responses carry a `google.rpc.Status` body with an `errorCode` in
  `error.details[]`; only `UNREGISTERED` (the token is permanently gone,
  APNs' `410`/`BadDeviceToken` equivalent) triggers delete + `unknown`.
  Anything else, including `INVALID_ARGUMENT`, is `failed` — a malformed
  *request* doesn't mean the *token* is dead, and `unknown` is destructive
  (see below), so don't conflate the two (`app/fcm.py::FcmResult.should_forget_device`).
- If the provider a stored token needs isn't configured (e.g. an FCM token
  is registered but `FCM_PROJECT_ID`/`FCM_SERVICE_ACCOUNT_PATH` are unset),
  that entry counts as `failed` — never a crash, never silently dropped.

**Response Nextcloud expects**, and enforces via
`Push::sendNotificationsToProxies()` reading `unknown`/`failed` from the
body (around line 761 onward) and, for anything listed in `unknown`, calling
`Push::deleteProxyPushTokenByDeviceIdentifier()` (line 1169) to drop its own
copy of that registration:

```json
{"unknown": ["<deviceIdentifier>", "..."], "failed": 0}
```

- a `deviceIdentifier` this proxy has never seen → added to `unknown` while
  the fleet-wide destructive-deletion budget allows it; after that budget is
  exhausted it counts as `failed` instead;
- a malformed entry, a `pushTokenHash` that doesn't match what we stored, a
  wrong-length or malformed `subject`, or a `signature` that fails
  verification → counts as `failed`, `unknown` untouched;
- APNs responds `410 Unregistered` or `400 BadDeviceToken` → the proxy
  deletes its own row *and* reports the `deviceIdentifier` as `unknown`, so
  Nextcloud's copy is cleaned up in the same round trip
  (`app/server.py::App.send_notifications`, `ApnsResult.should_forget_device`);
- any other APNs error (rate limit, bad topic, transient 5xx, ...) → counted
  as `failed`, the registration is kept (it may well still be valid).

**`unknown` is destructive.** Nextcloud deletes its own registration row for
every `deviceIdentifier` listed there (`Push::deleteProxyPushTokenByDeviceIdentifier()`,
line 1169). Nothing may ever land in that list except a genuine lookup miss
or a real APNs `410`/`BadDeviceToken` — that's why the lookup-miss check runs
*before* any other validation of an entry (a malformed field on an unknown
device is still just "unknown", never smuggled in as something else) and why
every other rejection path counts as `failed` instead.

### 5. `GET /health`

`{"status": "ok", "devices": <row count>}`. No auth; used for the container
healthcheck and external uptime checks. Reveals nothing but a row count.

## Security model — what's real, what's a documented gap

**Registration (`POST /devices`).** The signature check proves the caller
holds the private key matching `userPublicKey`, and that they used it to
sign this exact `deviceIdentifier` digest. On its own that is **not** proof
the caller is the legitimate Nextcloud user: `deviceIdentifier` is a public
value, so anyone could generate their own keypair and self-sign a
`deviceIdentifier` they merely observed (see
`tests/test_server.py::test_register_device_self_consistent_forgery_is_rejected_by_key_pin`,
which forges exactly this and proves the signature check alone accepts it).
What actually stops a hijack is **first-write pinning**: `DeviceStore`
rejects any later registration of an already-known `deviceIdentifier` under
a different `userPublicKey` (`403 Forbidden`). A device can freely refresh
its `pushToken` (reinstall, token rotation) as long as it keeps proving
ownership of the *original* key. The check and the write are one atomic SQL
statement (`INSERT ... ON CONFLICT ... DO UPDATE ... WHERE
devices.user_public_key = excluded.user_public_key`, `app/db.py::DeviceStore.register`)
— it used to be a separate `SELECT` before the `INSERT`, which let two
concurrent first-registrations under different keys both pass the check
before either had written anything (reproduced live: 7 of 8 concurrent
attempts "won" when only one should have;
`tests/test_db.py::test_concurrent_first_registrations_under_different_keys_never_corrupt`).
(This returns `403`, not the push-v2 `409`
"conflict, retry with `cloudId`" — this proxy doesn't implement the
`cloudId` retry flow, so `409` would tell the client to retry something that
can never succeed. `403` "unauthorized for this identifier" is honest about
that.)

**What this does not close:** an attacker who somehow learns a
`deviceIdentifier` *before* its real owner ever registers can squat on it —
register their own key first, forcing the real registration to be rejected
instead of succeeding. That requires knowing a Nextcloud-internal value
(`cloudId` + session token id, hashed) in advance, which this proxy has no
way to produce or predict; it is not exposed anywhere a third party can
read it before the legitimate client registers. Closing this completely
would mean cross-checking the caller's claimed identity against Nextcloud's
public identity-proof endpoint (`/ocs/v2.php/identityproof/key/{userid}`) —
that requires the client to also send its Nextcloud user id at registration
time, which the current wire contract (step 2 above) does not include.
Documented here rather than faked: implementing this would need a protocol
extension on the client side, out of scope for this repo alone.

**`userPublicKey` is bounds-checked, not just "does it parse as RSA".**
`crypto.load_rsa_public_key` rejects anything outside 2048-8192 bits
(`app/crypto.py::_MIN_RSA_KEY_BITS`/`_MAX_RSA_KEY_BITS`). Below 2048 is a
real crack target, not just theoretically weaker; above 8192 makes every
signature verify against that key disproportionately expensive, and
registration is free to attempt (no auth gate before the signature check —
see above), so an oversized key is a real CPU-amplification knob, not a
hypothetical one. 8192 is generous headroom above any real identity-proof
key Nextcloud actually issues.

**Deliberately not built: per-key registration quotas or storage
cleanup.** An attacker with an unlimited supply of keypairs can still
register an unlimited number of rows (disk fill). Not adding a cap here:
every legitimate row already requires a signature (an actual asymmetric
keypair, not a free-form string), so the cost-per-row for an attacker is
one RSA keygen — cheap, but not free, and nothing this proxy has ever
logged suggests it's been tried. A quota needs a policy decision this
proxy can't make unilaterally (quota per what — IP? there's no stable
per-*user* identity available at `POST /devices` time, see the squatting
paragraph above) and its own abuse surface (a cap enables a denial trigger
against a legitimate user who lost and re-registers many devices). Cheapest
real mitigation if this becomes a live problem: disk-usage alerting on the
container volume plus a manual `DELETE FROM devices WHERE created_at <
...` sweep, not new code — revisit if `GET /health`'s device count ever
grows in a way that isn't explained by real registrations.

**Notification delivery (`POST /notifications`).** The subscription key and
the `signature` check against the pinned `userPublicKey` authenticate this
endpoint: only someone holding the
Nextcloud server's identity-proof private key for that user (i.e., the real
Nextcloud server) can produce a signature that verifies. On top of that,
The subscription key uses the **native** mechanism Nextcloud already has for
exactly this: `Push::sendNotificationsToProxies()` sends an
`X-Nextcloud-Subscription-Key` header whenever `proxyServer` matches the
server's `subscription_aware_server` app config value. Set
`NEXTCLOUD_SUBSCRIPTION_KEY` to that value and every `/notifications`
request without a matching header gets `401` (`hmac.compare_digest`, no
timing side-channel). **Fails closed when unset**: the process logs a
warning on startup, and every `/notifications` call gets `401` until you
set it — a missing/misconfigured key must never be equivalent to "no auth
needed" (a strict `if key and not hmac.compare_digest(...)` used to allow
exactly that; flipped to `if not key or not hmac.compare_digest(...)`).
`/devices` is unaffected either way and keeps working during bring-up: it's
never gated by this key at all — see below. **This header is never sent to
`/devices`** — that call comes from the client, not the server, so
`/devices` keeps relying on the signature + key-pin above; it cannot use
this key.

**DoS/abuse guards, all in `app/server.py`:**
- `Content-Length` is validated before anything reads a body: missing means
  0, non-numeric or **negative is rejected outright** (`400`). `int()` alone
  accepts `"-1"` happily, and `self.rfile.read(-1)` means "read until EOF"
  in Python, not "no body" -- an unauthenticated client sending a negative
  `Content-Length` turned the size check below (`length > MAX_BODY_BYTES`,
  false for `-1`) into a request that holds a worker thread open until the
  peer closes on its own, i.e. never (`Handler._content_length`,
  reproduced live and in `test_negative_content_length_is_rejected_not_read_forever`).
  `DELETE /devices` goes through the identical check (`Handler._validate_length`)
  and the same per-IP bucket as `POST /devices` -- it used to read a body
  with neither;
- the handler also sets a 10s socket `timeout` (stdlib
  `StreamRequestHandler`, applies to every blocking read on the connection,
  not just the request line) -- `ThreadingHTTPServer` has no cap on
  concurrent threads, so without this a client that opens a connection and
  never finishes sending holds a thread open indefinitely regardless of
  Content-Length;
- request bodies over 1 MiB (`MAX_BODY_BYTES`) get `413` without being
  parsed. Getting that `413` to actually arrive at the client, through the
  Apache/ISPConfig reverse proxy in front of this service, took three
  separate fixes, all load-bearing -- removing any one of them regresses a
  reproduced live failure, not a theoretical one:
  1. `protocol_version = "HTTP/1.1"` on the handler. At the stdlib default
     (`HTTP/1.0`), `handle_expect_100` is never invoked, so a client/proxy
     sending `Expect: 100-continue` for a large upload never gets a
     `100 Continue` and waits forever -- reproduced live as the reverse
     proxy hanging indefinitely on a >1MiB POST, tying up a shared Apache
     worker.
  2. Reject *inside* `do_POST`, after stdlib's default `100 Continue`, not
     before it. An earlier attempt rejected before sending `100 Continue`
     at all -- that also stopped the hang, but the live proxy then
     substituted its own generic error page for the early rejection
     instead of relaying it, so the client saw a `404` instead of `413`.
  3. Draining a *generous*, fixed amount of the rejected body
     (`_DRAIN_CAP_BYTES`, 8 MiB) before responding, not a token amount.
     `mod_proxy_http` writes the whole request body to us before it will
     accept any response from us as valid; stopping too early (previously
     tried: nothing, then 64 KiB) leaves it mid-write when we close, which
     it reports as its own `502` instead of relaying our `413` --
     reproduced live at 1.2 MiB and 2 MiB bodies with a 64 KiB cap, fixed by
     widening it. The cap is still a fixed constant *we* choose, never the
     client's declared `Content-Length` -- that's what keeps this bounded
     rather than a reopened version of the same DoS. Bodies large enough to
     exceed even the 8 MiB cap (tested at 10 MiB) still get the proxy's
     generic error page instead of a clean `413`; the rate limiter below
     bounds how often one source can trigger that, and no legitimate
     client ever sends a body anywhere close to that size;
- `POST /devices` (and `DELETE /devices`, same bucket) is rate-limited per
  source IP (token bucket, 20 burst / 20 per minute refill) — `429` past
  that; `POST /notifications` has a looser per-IP bucket (120/120 per
  minute) for the same reason, since real Nextcloud traffic can burst. Each
  `RateLimiter`'s bucket dict is itself bounded: a bucket only gets evicted
  once it's both back at full capacity and idle an hour, so evicting one is
  exactly equivalent to it never having existed — otherwise a caller cycling
  through distinct keys grows that dict forever;
- **`X-Forwarded-For` is only trusted from `TRUSTED_PROXY_IP`** (the reverse
  proxy in front of this service), and only its **last** entry. Unset (the
  default) means never trust it, rate-limit by the raw TCP peer instead.
  Two separate mistakes here, both real: trusting the header from *any*
  peer means anyone can put a fresh fake IP in it per request and dodge
  every limit; and even from the *real* proxy, `mod_proxy_http` **appends**
  the genuine peer to whatever `X-Forwarded-For` the client already sent
  rather than replacing it, so the first entry can still be
  attacker-supplied — only the last one is what the trusted hop itself
  added (`Handler._client_ip`);
- `subject` must be exactly 344 base64 chars (an RSA-2048 ciphertext is
  always exactly 256 bytes) — anything else is rejected before spending a
  public-key verify on it;
- a batch is capped at 100 `notifications[N]` entries; anything past the
  cap is not processed and counts as `failed`, so an oversized batch is
  visible instead of silently truncated;
- `pushToken` must match one of two shapes before it's ever touched by
  `apns.py`'s `f"/3/device/{device_token}"` or handed to FCM, closing off
  path injection: an APNs token is `^(?:[0-9a-f]{2}){32,100}$` (64-200
  lowercase hex chars — real APNs tokens vary in length, unlike the fixed
  64-char sha512 hex Nextcloud uses for `pushTokenHash`, so this is
  deliberately wider than that), an FCM token is
  `^[A-Za-z0-9_:-]{32,4096}$`. `token_kind()` tries the APNs pattern first
  since it's the narrower one — FCM's charset is technically a superset
  that would also match plain hex.

**Replay is a Nextcloud protocol property, not a bug this proxy
introduces or can unilaterally fix.** The wire format
(`deviceIdentifier`/`subject`/`signature`) has no nonce or timestamp
anywhere upstream — Nextcloud's own push proxy has exactly the same
exposure, since the signature alone is what authenticates a
`notifications[N]` entry. Extending the format would break compatibility
with the real Nextcloud server, which is not this proxy's protocol to
change. What we *do* control is bounding the blast radius: dedupe by
`(deviceIdentifier, signature)` within a 5-minute TTL, so a captured entry
can be replayed at most once per window rather than indefinitely. The guard
uses an in-flight lease and only commits it after the provider accepts the
push. A repeat after success is silently dropped (counted as neither
`failed` nor `unknown`), a concurrent repeat while the first send is still
running counts as `failed`, and a transient provider failure releases the
lease so a later retry can actually reach APNs or FCM instead of being
misreported as already delivered. Active leases do not expire while a
provider call is in flight; provider clients have a 10-second network timeout.
Committed entries expire after five minutes. The guard holds at most 16,384
active and committed entries combined; a new key at that ceiling counts as
`failed` instead of growing memory without a bound.

The lease is intentionally in-memory; it is not a durable retry queue.
Current Nextcloud logs the proxy's non-zero `failed` count but does not
re-enqueue that encrypted payload. Persisting retries here would therefore
need a real bounded outbox with expiry, cancellation for stale/delete pushes,
and crash-safe leases -- not an inline HTTP retry that can duplicate or show
stale notifications. Until that protocol slice exists, a later identical
request is safe to retry, but the proxy does not invent one on its own.

**Storage.** `push_token` (the real APNs device token) is stored in
cleartext SQLite, file permissions restricted to the container user
(`chmod 600`, `app/db.py`). It is not secret in the sense of being
independently exploitable — delivering a push additionally requires this
service's own APNs key and the correct topic — but treat `data/devices.db`
and its backups as sensitive.

**Network exposure.** The container binds `LISTEN_HOST=0.0.0.0` *inside*
its own network namespace (it's the only process in there, that's normal),
but `docker-compose.yml` only publishes that port to `BIND_ADDR` on the
host — default `127.0.0.1`, so nothing reaches it without also being on the
host itself, unless explicitly overridden to the host's LAN IP for a
reverse proxy on a different machine (see Deployment). The `.p8` key is
mounted `:ro`.

## Endpoints

| Method | Path | Auth | Rate limit | Purpose |
| --- | --- | --- | --- | --- |
| `GET`/`HEAD` | `/health` | none | none | liveness + device count |
| `POST` | `/devices` | RSA signature over `deviceIdentifier` | 20 burst, 20/min per IP | register/refresh a device |
| `DELETE` | `/devices` | RSA signature, verified against the stored key | none | unregister a device |
| `POST` | `/notifications` | RSA signature per entry + required `X-Nextcloud-Subscription-Key` | 120 burst, 120/min per IP | Nextcloud → APNs/FCM relay |

## Environment variables

See `.env.example` for the full annotated list. Summary:

| Variable | Required | Meaning |
| --- | --- | --- |
| `APNS_KEY_PATH` | one of APNs/FCM | path to the `.p8` APNs auth key inside the container |
| `APNS_KEY_ID` | one of APNs/FCM | the key's Key ID (Apple Developer portal) |
| `APNS_TEAM_ID` | one of APNs/FCM | Apple Developer Team ID |
| `APNS_TOPIC` | no (default `com.nkshub.nextcloudtalk`) | app bundle id / APNs topic |
| `APNS_USE_SANDBOX` | no (default `0`) | fallback for legacy APNs registrations without `pushEnvironment`; `1` = development, `0` = production |
| `FCM_PROJECT_ID` | one of APNs/FCM | Google Cloud/Firebase project ID this proxy sends through |
| `FCM_SERVICE_ACCOUNT_PATH` | one of APNs/FCM | path to the service account JSON inside the container |
| `DB_PATH` | no (default `/data/devices.db`) | SQLite file |
| `LISTEN_HOST` / `LISTEN_PORT` | no (default `0.0.0.0` / `8080`) | bind address (container-internal) |
| `NEXTCLOUD_SUBSCRIPTION_KEY` | no (unset disables `/notifications` with `401` and logs a startup warning) | matches Nextcloud's `X-Nextcloud-Subscription-Key`, see Security model |
| `NEXTCLOUD_SUBSCRIPTION_KEYS` | no | comma-separated keys of further Nextcloud servers sharing this proxy; each server keeps its own `push_subscription_key`, any listed key is accepted on `/notifications` |
| `APNS_KEY_HOST_PATH` | docker-compose only | absolute host path to the real `.p8` file |
| `FCM_SERVICE_ACCOUNT_HOST_PATH` | docker-compose only | absolute host path to the real service account JSON |
| `BIND_ADDR` | docker-compose only (default `127.0.0.1`) | host address the container port is published on — see Security model |

**At least one of APNs (all three `APNS_*` required fields) or FCM (both
`FCM_*` required fields) must be configured, or the service refuses to
start** — `app/config.py::Config.__post_init__`. Either can be left
entirely unset to run with just the other provider; the missing one logs a
startup warning and any notification needing it counts as `failed` rather
than crashing anything (`app/__main__.py`).

Neither the `.p8` private key nor the FCM service account JSON is ever an
environment variable and never committed — both are bind-mounted read-only
into the container.

## Running locally

```bash
python -m venv .venv && . .venv/Scripts/activate   # or bin/activate on Linux/macOS
pip install -r requirements-dev.txt
cp .env.example .env   # fill in real APNs values, or point APNS_KEY_PATH at a test key
python -m app
pytest
```

## Docker

```bash
cp .env.example .env
# edit .env: real APNS_KEY_ID / APNS_TEAM_ID / APNS_TOPIC / APNS_KEY_HOST_PATH
docker compose build
docker compose up -d
curl http://localhost:8080/health
```

## Deployment

Deployed as a plain Docker Compose service, following this environment's
existing convention for small internal services (git checkout on the
target host, `docker compose build && docker compose up -d`, no CI/CD
pipeline for this repo). Concretely:

```bash
ssh <docker-host>
mkdir -p /opt/nks-talk-notify/secrets
# copy the .p8 key out-of-band (scp from a secrets store, never through git)
cd /opt/nks-talk-notify
git clone <this repo> .
cp .env.example .env
$EDITOR .env   # set real APNS_KEY_ID/TEAM_ID/TOPIC and APNS_KEY_HOST_PATH
# the container runs as uid 10001; the bind-mounted data dir must be
# writable by it, or dockerd will create it root-owned on first run
mkdir -p data && chown 10001:10001 data
docker compose build
docker compose up -d
docker compose logs -f --tail 50
curl http://127.0.0.1:8080/health
```

A reverse proxy in front of the container terminates public HTTPS for the
proxy's public hostname and forwards to this container's port; that part is
environment-specific infrastructure, not part of this repo. If that reverse
proxy runs on a **different host** than this container (as it does here —
see the topology note below), set `BIND_ADDR` in `.env` to this host's LAN
IP instead of the default `127.0.0.1`, and nothing wider than that:
`0.0.0.0` would also accept connections from any other network this host is
on, not just the one the proxy is reachable from.

Once the reverse proxy is verified working, register this proxy's URL as
Nextcloud's `subscription_aware_server` and set `NEXTCLOUD_SUBSCRIPTION_KEY`
to match (see Security model above), then `docker compose up -d` to pick it
up — this can be done any time after initial bring-up, it doesn't need to
happen before the first deploy.

**Topology used for the reference deployment** (example.com infrastructure):
this container runs on a Docker host reachable only from the internal LAN;
a separate host runs ISPConfig-managed Apache, which is what's actually
reachable from the public internet (`*.example.com` wildcard DNS → NAT →
that host) and holds the Let's Encrypt certificate. Adding a new public
`*.example.com` hostname therefore means adding an ISPConfig site on *that*
host with `apache_directives` doing a reverse proxy to
`http://<docker-host-lan-ip>:<port>/`, not touching this repo or its
Dockerfile at all. Don't hand-edit Apache vhosts directly on that host —
ISPConfig owns and regenerates them; the reference deployment's
`apache_directives` were set through the ISPConfig Remote API, scoped to
this one site only.

That `apache_directives` block also sets `LimitRequestBody 1048576`
(matching `MAX_BODY_BYTES`) as defense-in-depth at the proxy layer. On its
own it did **not** fix the reverse-proxy body-size interaction described
under Security model -- the real fix there is the widened drain cap in
`app/server.py`. Keep both: the Apache-level limit protects requests that
never should have started relaying at all, the app-level cap and drain
handle everything that does.

### Recovery

State is a single SQLite file (`DB_PATH`, default `/data/devices.db` /
`./data/devices.db` on the host via the compose bind mount). To restore
after a host failure: recreate `/opt/nks-talk-notify` from git, restore
`data/devices.db` from backup (or start empty — devices simply
re-register themselves on next app launch/token refresh, Nextcloud
naturally repopulates `unknown` cleanup on the next push if a stale copy
lingers), restore the `.p8` key from the secrets store, `docker compose up
-d`.

### Rotating the APNs key

1. Apple Developer portal → Keys → create a new key with the "Apple Push
   Notifications service (APNs)" capability, note its Key ID.
2. Copy the new `.p8` to the host, e.g.
   `/opt/nks-talk-notify/secrets/AuthKey_<NEWID>.p8`.
3. Update `.env`: `APNS_KEY_ID` and `APNS_KEY_HOST_PATH`.
4. `docker compose up -d` (recreates the container with the new mount).
5. Verify: `docker compose logs --tail 20` shows a clean start, then trigger
   a real notification and confirm it arrives.
6. Once confirmed, revoke the old key in the Apple Developer portal and
   delete the old `.p8` file from the host.

No client-side change is needed — the key id/team id only affect how this
proxy authenticates to Apple, not the wire contract with Nextcloud or the
app.

### Rotating the FCM service account

1. Firebase Console → Project Settings → Service Accounts → Generate new
   private key, for the same project (`FCM_PROJECT_ID`). The old key keeps
   working until you revoke it.
2. Copy the new JSON to the host, e.g.
   `/opt/nks-talk-notify/secrets/fcm-service-account-<date>.json` — next to
   the `.p8`, same `chown` to the container user + `chmod 400`.
3. Update `.env`: `FCM_SERVICE_ACCOUNT_HOST_PATH`.
4. `docker compose up -d` (recreates the container with the new mount).
5. Verify from the logs that the OAuth2 exchange succeeds: a line for
   `POST https://oauth2.googleapis.com/token` returning `200`. A `401` or
   `invalid_grant` there means the key, the `client_email`, or the clock is
   wrong — it is not a token problem yet, don't go looking at device tokens
   first. Once that's clean, trigger a real notification and confirm it
   arrives.
6. Once confirmed, delete/disable the old service account key in the
   Firebase Console and remove the old JSON from the host.

No client-side change is needed here either — same reasoning as the APNs
key.

### APNs development and production environments

Current clients register `pushProvider=apns` and
`pushEnvironment=development|production` with each APNs device. Android
registers `pushProvider=fcm` without an environment. The proxy keeps clients
for both Apple endpoints open and routes
each notification according to that stored value. Debug builds use
development; Profile, Release, TestFlight, and App Store builds use
production. Both kinds can therefore coexist in one deployment.

`APNS_USE_SANDBOX` is only the fallback for registrations created before the
per-device field existed. Set it to the environment of that legacy fleet and
let current clients refresh their registrations. Once every APNs row has an
explicit environment, changing the fallback has no effect on them.

**Why the whole fleet doesn't actually get deregistered when this happens:**
Apple can't tell "this token belongs to the other environment" apart from
"this token is genuinely dead (uninstalled, expired)" — both come back as
`BadDeviceToken`, and per the wire contract that's supposed to mean
"forget this device, tell Nextcloud too" (`unknown`, which is destructive).
Flip the fallback against a legacy fleet still registered under the old one
and every legacy device would fail that way at once. `App.deletion_breaker` (a
`RateLimiter` reused as a shared budget, not a per-caller gate — see
`app/server.py::App.__init__`) caps *destructive* dead-token cleanup at
10/hour across the whole fleet, however many separate `/notifications`
calls that arrives across. Past the cap, further "dead" devices are logged
at `error` level and counted as `failed` instead of being deleted — kept,
not silently dropped, until whoever's watching the logs sorts out whether
it's real churn or a mismatched environment. Considered and rejected:
requiring re-registration on every environment switch (no wire-contract
hook to force that from the proxy side) and a per-batch threshold instead
of a rolling one (real Nextcloud traffic sends one or a few notifications
per call, not the whole fleet at once — a mismatch incident shows up as
many *separate* small calls in a short window, which a per-batch cap alone
wouldn't catch). 10/hour is a judgment call: generous for whatever organic
device churn a proxy this size sees, tight against an incident that tries
to empty the whole fleet within the first notification round after a flip.

### Reading the logs

`docker compose logs` — timestamps are **UTC**, not local time; a line that
looks two hours old is usually two minutes old, compare against `date -u`,
not your own clock.

**Every request logs the reverse proxy's address, not the caller's** — the
access log prints the raw socket peer, and behind the reverse proxy that's
the proxy's own LAN IP (`192.0.2.10` in the reference deployment). The
rate limiter reads `X-Forwarded-For` and does see the real client for its
own decisions, but the access log line itself does not — don't conclude
from it that traffic came from inside the network. A real client IP, if
you need one, is in the reverse proxy's own access log, not here.

Provider-client request logging is suppressed below WARNING. `httpx` includes
the complete URL in every INFO access line, and APNs places the device token
directly in `/3/device/<token>`; keeping those otherwise-useful lines would
persist real push tokens in container logs. This service's own failure logs
remain: APNs reports status/reason and FCM reports status/error code without
including the token. An FCM OAuth failure therefore still points to service
account/authentication configuration, while a send failure points to the
message or registration token (see the error-code table under Security
model), but successful provider requests are intentionally quiet.

### Live verification against the running proxy

`/health`'s device count is the only way anyone outside this repo can
confirm from the outside whether a *real* registration went through — the
mobile teams read it too. A leftover synthetic device from a smoke test
pollutes that signal for everyone, and is orphaned (Nextcloud never knows
about a device that only exists in this proxy's DB), so nobody can safely
delete it later without asking around — losing a real device's row to a
guess is worse than the clutter (it happened once during development).

Rules for any one-off script that registers a device against the live
proxy (`make_fake_device()` from `tests/conftest.py` or equivalent):

- **Always pass a `preimage` starting with a reserved marker no real
  registration can ever produce**, e.g. `SMOKETEST:` — a real preimage is
  always Nextcloud's own `[cloudId, tokenId]` JSON
  (`PushController::registerDevice`), which never looks like that. Add a
  run-unique suffix too, or repeated runs collide under the key pin
  (`403`): `f'SMOKETEST:{time.time()}'.encode()`. This is what makes a
  leftover row identifiable *without guessing* if a script dies before
  cleanup — the point that mattered enough to cost a real device's row
  once already.
- **Clean up in the same script**, right after you're done, not "I'll
  delete it after": `DELETE /devices` with that device's own
  `deviceIdentifier` + `deviceIdentifierSignature`.
- Nothing marks a synthetic device as synthetic server-side — there's no
  field for it and there shouldn't be (it'd be one more thing to keep
  honest). The reserved preimage prefix *is* the marker.

The negative checks below don't register anything, so they're always safe
to run without touching `/health`'s count:

```bash
# 401 without the subscription key (skip if NEXTCLOUD_SUBSCRIPTION_KEY is unset)
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://<host>/notifications \
  --data-urlencode 'notifications[0]={"deviceIdentifier":"x","pushTokenHash":"x","subject":"x","signature":"x"}'
# → 401

# 400 on a token matching neither APNs nor FCM shape
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://<host>/devices \
  --data-urlencode 'pushToken=not-a-valid-token!!' \
  --data-urlencode 'deviceIdentifier=x' --data-urlencode 'deviceIdentifierSignature=x' --data-urlencode 'userPublicKey=x'
# → 400 {"message": "INVALID_PUSH_TOKEN"}

# 413 on a body over MAX_BODY_BYTES (1 MiB) -- must come back in well under
# a second; if it hangs or comes back as a proxy-generated 502/404 instead
# of our own JSON, the reverse-proxy interaction described under Security
# model has regressed, not this check
head -c 1100000 /dev/zero | tr '\0' 'a' > /tmp/big.txt
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://<host>/devices --data-binary @/tmp/big.txt
# → 413
```

### Troubleshooting: notifications aren't arriving

1. `curl https://<public-host>/health` — if this fails, it's a reverse
   proxy / container problem, not a push problem.
2. `docker compose logs -f nks-talk-notify` — every `POST /notifications`
   logs a `failed`/`unknown` outcome per entry; a `subject signature failed
   verification` line means either data corruption or that the caller isn't
   really Nextcloud (or the stored `userPublicKey` doesn't match what
   Nextcloud currently has for that user — re-register the device).
3. Confirm registration ever happened: `GET /health` device count should be
   > 0; check `data/devices.db` directly (`sqlite3 data/devices.db "select
   device_identifier, updated_at from devices"`) if you have shell access.
4. Confirm Nextcloud is even trying: on the Nextcloud server,
   `occ notification:test-push <user>` (if available) or check
   `nextcloud.log` for `Could not send notification to push server`
   entries — those come from `Push::sendNotificationsToProxies()` and
   include the HTTP status/error this proxy returned.
5. APNs-side rejection shows up in this proxy's logs as `APNs push failed:
   status=... reason=...` — common reasons: `BadDeviceToken` (also
   auto-deletes the device — expected after a reinstall on a new
   provisioning profile, but **also the exact symptom of a sandbox/production
   mismatch**: a debug device token only works against
   `api.sandbox.push.apple.com`, while Profile, Release, TestFlight, and App
   Store tokens only work against `api.push.apple.com`. Current clients avoid
   the mismatch by registering `pushEnvironment` per device. For a legacy row
   with no environment, check `APNS_USE_SANDBOX` against how the app was built),
   `BadTopic` (check `APNS_TOPIC` matches the
   app's actual bundle id), `TopicDisallowed` / `InvalidProviderToken` (Key
   ID or Team ID in `.env` is wrong, or the key was revoked).
6. Confirm the stored `push_provider` is `apns` and `push_environment` matches
   the build: `development` for
   debug and `production` for Profile, Release, TestFlight, or App Store. A
   null value is a legacy registration and uses `APNS_USE_SANDBOX` as fallback.
7. If nothing shows up in this proxy's logs at all: the client likely never
   registered `proxyServer` pointing at this service, or Nextcloud's own
   background job (`cron.php` / notify_push queue) isn't running, which is
   outside this proxy's control.

## What's intentionally not here

- No provider inference for current clients. `pushProvider` is authoritative;
  token-shape inference remains only for database rows created before that
  field existed.
- No multi-tenant support beyond what the wire contract already gives for
  free (any Nextcloud server can point `proxyServer` at this instance;
  there is nothing NKS-specific baked into the protocol handling).
- No admin UI. `data/devices.db` is a plain SQLite file; inspect it with
  the `sqlite3` CLI if needed.
