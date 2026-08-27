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
`200` if nothing was registered (idempotent), `202` on deletion, `400` if
the signature doesn't verify.

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
- a malformed entry, a `pushTokenHash` that doesn't match what we stored, or
  a `signature` that fails verification → counts as `failed`, `unknown`
  untouched;
- APNs responds `410 Unregistered` or `400 BadDeviceToken` → the proxy
  deletes its own row *and* reports the `deviceIdentifier` as `unknown`, so
  Nextcloud's copy is cleaned up in the same round trip
  (`app/server.py::App.send_notifications`, `ApnsResult.should_forget_device`);
- any other APNs error (rate limit, bad topic, transient 5xx, ...) → counted
  as `failed`, the registration is kept (it may well still be valid).

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
a different `userPublicKey` (`409 Conflict`). A device can freely refresh
its `pushToken` (reinstall, token rotation) as long as it keeps proving
ownership of the *original* key.

**What this does not close:** an attacker who somehow learns a
`deviceIdentifier` *before* its real owner ever registers can squat on it —
register their own key first, forcing the real registration to fail with
`409` instead of succeeding. That requires knowing a Nextcloud-internal
value (`cloudId` + session token id, hashed) in advance, which this proxy
has no way to produce or predict; it is not exposed anywhere a third party
can read it before the legitimate client registers. Closing this
completely would mean cross-checking the caller's claimed identity against
Nextcloud's public identity-proof endpoint
(`/ocs/v2.php/identityproof/key/{userid}`) — that requires the client to
also send its Nextcloud user id at registration time, which the current
wire contract (step 2 above) does not include. Documented here rather than
faked: implementing this would need a protocol extension on the client
side, out of scope for this repo alone.

**Notification delivery (`POST /notifications`).** No shared secret, no
auth header — matching the real Nextcloud protocol, which has none either.
The `signature` check against the pinned `userPublicKey` is the entire
authentication for this endpoint: only someone holding the Nextcloud
server's identity-proof private key for that user (i.e., the real
Nextcloud server) can produce a signature that verifies.

**Storage.** `push_token` (the real APNs device token) is stored in
cleartext SQLite. It is not secret in the sense of being independently
exploitable — delivering a push additionally requires this service's own
APNs key and the correct topic — but treat `data/devices.db` and its
backups as sensitive, and restrict filesystem access to the container user.

## Endpoints

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| `GET` | `/health` | none | liveness + device count |
| `POST` | `/devices` | RSA signature over `deviceIdentifier` | register/refresh a device |
| `DELETE` | `/devices` | RSA signature, verified against the stored key | unregister a device |
| `POST` | `/notifications` | RSA signature per notification, verified against the stored key | Nextcloud → APNs relay |

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
| `LISTEN_HOST` / `LISTEN_PORT` | no (default `0.0.0.0` / `8080`) | bind address |
| `APNS_KEY_HOST_PATH` | docker-compose only | absolute host path to the real `.p8` file |

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
environment-specific infrastructure, not part of this repo.

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
   provisioning profile), `BadTopic` (check `APNS_TOPIC` matches the app's
   actual bundle id and that `APNS_USE_SANDBOX` matches how the app was
   built), `TopicDisallowed` / `InvalidProviderToken` (Key ID or Team ID in
   `.env` is wrong, or the key was revoked).
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
