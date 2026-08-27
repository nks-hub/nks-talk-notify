# nks-talk-notify

A minimal, self-hosted push proxy that lets iOS push notifications reach a
**closed** NKS Talk app (`com.nkshub.nextcloudtalk`), the third-party
Nextcloud Talk client this project builds.

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
| `pushToken` | the real APNs device token (hex string) |
| `deviceIdentifier` | `base64(sha512(preimage))`, exactly as Nextcloud returned it |
| `deviceIdentifierSignature` | `base64(signature)`, exactly as Nextcloud returned it |
| `userPublicKey` | `publicKey`, exactly as Nextcloud returned it |

**Client contract that is not visible in this repo:** the `pushTokenHash`
the client sends to *Nextcloud* must equal `sha512(pushToken)` computed the
same way this proxy computes it — SHA-512 of the UTF-8 hex token string
(`app/server.py::App.push_token_hash`). If the mobile client hashes
differently (e.g. over raw token bytes instead of the hex string), delivery
lookups in `POST /notifications` will never match. Confirm this with
whoever implements the iOS registration flow.

See `app/crypto.py` for exactly how the signature is verified and why it
cannot be verified as a normal signature (the digest, not the preimage, is
all the proxy ever has).

Responses: `200` empty body on success (matches what current official
clients expect), `400` on a missing field or a signature that doesn't
verify, `409` if `deviceIdentifier` is already registered under a
*different* `userPublicKey` (see Security below).

### 3. `DELETE /devices`

Query params (form body also accepted): `deviceIdentifier`,
`deviceIdentifierSignature`. The signature is checked against the **stored**
public key, not one the caller supplies — otherwise anyone could delete any
registration just by presenting a signature over a key of their own choice.
`200` if nothing was registered (idempotent) or on deletion (push-v2 spec —
not `202`), `400` if the signature doesn't verify.

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
`crypto.verify_subject_signature`) before ever calling APNs — this is the
only thing standing between "any HTTP client on the internet" and pushing
arbitrary payloads to a real device, since this endpoint itself has no
other authentication.

**Response Nextcloud expects**, and enforces via
`Push::sendNotificationsToProxies()` reading `unknown`/`failed` from the
body (around line 761 onward) and, for anything listed in `unknown`, calling
`Push::deleteProxyPushTokenByDeviceIdentifier()` (line 1169) to drop its own
copy of that registration:

```json
{"unknown": ["<deviceIdentifier>", "..."], "failed": 0}
```

- a `deviceIdentifier` this proxy has never seen → added to `unknown`,
  does **not** count as `failed`;
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
ownership of the *original* key. (This returns `403`, not the push-v2 `409`
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

**Notification delivery (`POST /notifications`).** By default, no shared
secret. The `signature` check against the pinned `userPublicKey` is the
entire authentication for this endpoint: only someone holding the
Nextcloud server's identity-proof private key for that user (i.e., the real
Nextcloud server) can produce a signature that verifies. On top of that,
this proxy supports the **native** mechanism Nextcloud already has for
exactly this: `Push::sendNotificationsToProxies()` sends an
`X-Nextcloud-Subscription-Key` header whenever `proxyServer` matches the
server's `subscription_aware_server` app config value. Set
`NEXTCLOUD_SUBSCRIPTION_KEY` to that value and every `/notifications`
request without a matching header gets `401` (`hmac.compare_digest`, no
timing side-channel). Leave it unset only for first bring-up — the process
logs a warning on startup and the endpoint stays reachable by anyone who can
route to it. **This header is never sent to `/devices`** — that call comes
from the client, not the server, so `/devices` keeps relying on the
signature + key-pin above; it cannot use this key.

**DoS/abuse guards, all in `app/server.py`:**
- request bodies over 1 MiB get `413` without being parsed;
- `POST /devices` is rate-limited per source IP (token bucket, 20 burst /
  20 per minute refill) — `429` past that;
- `POST /notifications` has a looser per-IP bucket (120/120 per minute) for
  the same reason, since real Nextcloud traffic can burst; behind the
  reverse proxy "per IP" effectively means "per proxy hop" unless
  `X-Forwarded-For` carries the real client, which this proxy reads if
  present;
- `subject` must be exactly 344 base64 chars (an RSA-2048 ciphertext is
  always exactly 256 bytes) — anything else is rejected before spending a
  public-key verify on it;
- a batch is capped at 100 `notifications[N]` entries; anything past the
  cap is not processed and counts as `failed`, so an oversized batch is
  visible instead of silently truncated;
- `pushToken` must match `^[0-9a-f]{64}$` (lowercase only, to stay
  consistent with the sha512 hex Nextcloud itself requires for
  `pushTokenHash`) — this closes off `apns.py`'s
  `f"/3/device/{device_token}"` as a path-injection vector, since anyone
  with a self-consistent signature (see above) can reach `POST /devices`
  from any Nextcloud server, not just this deployment's own.

**Replay.** The native protocol has no nonce or timestamp, so a captured
`notifications[N]` entry is replayable indefinitely on its own. Rather than
extend the wire format (breaking compatibility with the real Nextcloud
server), this proxy dedupes by `(deviceIdentifier, signature)` within a
5-minute TTL window — a repeat within that window is silently dropped
(counted as neither `failed` nor `unknown`, i.e. treated as already
delivered) instead of triggering a second APNs push.

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
| `POST` | `/notifications` | RSA signature per entry + optional `X-Nextcloud-Subscription-Key` | 120 burst, 120/min per IP | Nextcloud → APNs relay |

## Environment variables

See `.env.example` for the full annotated list. Summary:

| Variable | Required | Meaning |
| --- | --- | --- |
| `APNS_KEY_PATH` | yes | path to the `.p8` APNs auth key inside the container |
| `APNS_KEY_ID` | yes | the key's Key ID (Apple Developer portal) |
| `APNS_TEAM_ID` | yes | Apple Developer Team ID |
| `APNS_TOPIC` | no (default `com.nkshub.nextcloudtalk`) | app bundle id / APNs topic |
| `APNS_USE_SANDBOX` | no (default `0`) | `1` to talk to `api.sandbox.push.apple.com` (debug/TestFlight builds) |
| `DB_PATH` | no (default `/data/devices.db`) | SQLite file |
| `LISTEN_HOST` / `LISTEN_PORT` | no (default `0.0.0.0` / `8080`) | bind address (container-internal) |
| `NEXTCLOUD_SUBSCRIPTION_KEY` | no (unset = `/notifications` unauthenticated, logs a startup warning) | matches Nextcloud's `X-Nextcloud-Subscription-Key`, see Security model |
| `APNS_KEY_HOST_PATH` | docker-compose only | absolute host path to the real `.p8` file |
| `BIND_ADDR` | docker-compose only (default `127.0.0.1`) | host address the container port is published on — see Security model |

The `.p8` private key itself is **never** an environment variable and never
committed — it is bind-mounted read-only into the container.

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
ISPConfig owns and regenerates them.

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
   mismatch**: a device token issued by a debug/TestFlight build only works
   against `api.sandbox.push.apple.com`, a device token from an App Store
   build only works against `api.push.apple.com`; this proxy only ever talks
   to one of the two, chosen by `APNS_USE_SANDBOX`. If every device gets
   silently deleted right after registering, this is almost certainly the
   cause — check `APNS_USE_SANDBOX` against how the app was actually built,
   not the other way around), `BadTopic` (check `APNS_TOPIC` matches the
   app's actual bundle id), `TopicDisallowed` / `InvalidProviderToken` (Key
   ID or Team ID in `.env` is wrong, or the key was revoked).
6. This proxy talks to exactly one APNs environment at a time
   (`APNS_USE_SANDBOX`). It cannot simultaneously serve TestFlight/debug
   builds and an App Store release — if both exist at once, that needs two
   deployments (two ports/hosts) or a client-side environment field added to
   the registration contract, neither of which exists today.
6. If nothing shows up in this proxy's logs at all: the client likely never
   registered `proxyServer` pointing at this service, or Nextcloud's own
   background job (`cron.php` / notify_push queue) isn't running, which is
   outside this proxy's control.

## What's intentionally not here

- No FCM/Android path — this proxy is APNs/iOS only.
- No multi-tenant support beyond what the wire contract already gives for
  free (any Nextcloud server can point `proxyServer` at this instance;
  there is nothing NKS-specific baked into the protocol handling).
- No admin UI. `data/devices.db` is a plain SQLite file; inspect it with
  the `sqlite3` CLI if needed.
