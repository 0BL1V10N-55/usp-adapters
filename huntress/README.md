# Huntress Adapter

Pulls events from the [Huntress](https://www.huntress.com/) REST API
(`https://api.huntress.io/v1`, documented at
[api.huntress.io/docs](https://api.huntress.io/docs)) into LimaCharlie. Events
are forwarded in their original Huntress JSON form — the adapter does not
reshape payloads.

## What it collects

The adapter polls **Signals** (`GET /v1/signals`) — Huntress's unified
security-detection feed. A Signal is emitted for interesting user or system
behavior an analyst can reference during an investigation, ranging from low-
fidelity (e.g. a `whoami` command line) to high-fidelity (e.g. a known malware
file). Signal types include Antivirus, Footholds, Process Insights, Managed
ITDR, MDE Detections, SIEM, Ransomware Canaries, Favicon Detections, Attack
Disruptions and App Control.

Every shipped event has `EventType: "signals"`. A sample payload:

```json
{
  "id": 1,
  "created_at": "2025-06-26T18:57:03Z",
  "updated_at": "2025-06-26T18:57:03Z",
  "name": "Firewall Disabled via Netsh",
  "type": "Process Insights",
  "status": "closed",
  "details": {
    "rule_name": "Firewall Disabled via Netsh",
    "username": "admin22",
    "process_name": "C:\\WINDOWS\\system32\\netsh.exe",
    "command_line": "NetSh.exe  Advfirewall set allprofiles state off"
  },
  "entity": { "id": 72183, "name": "Laptop 52", "type": "agent" },
  "organization": { "id": 232, "name": "Huntress" }
}
```

## Authentication

Generate an API key/secret pair under **Account > API Credentials** in the
Huntress portal (requires your account be granted API access). The secret is
shown only once at generation time. The adapter sends both as an HTTP Basic
`Authorization` header: `Basic base64(api_key:api_secret)`.

A single credential pair is account-scoped and can see every organization the
account manages — no per-organization credential is needed. Use
`organization_id` (below) to narrow collection to one organization.

## Configuration

| Key | Required | Description |
|-----|----------|-------------|
| `client_options` | yes | Standard USP adapter options (see the repo README). |
| `api_key` | yes | Huntress API public key. |
| `api_secret` | yes | Huntress API private key. |
| `base_url` | no | Full API root override. Default `https://api.huntress.io/v1`. |
| `organization_id` | no | Scope collection to a single Huntress organization. Default: every organization the credentials can see. |
| `types` | no | List of Signal types to collect (e.g. `["Antivirus", "Footholds"]`). Default: every type. See the [API docs](https://api.huntress.io/docs) for the full enumeration. |
| `statuses` | no | List of Signal statuses to collect (`reported`, `closed`). Default: every status. |
| `limit` | no | Records requested per page. Default `500` (the API's own maximum). |
| `poll_interval` | no | Wait between polls, as a Go duration in nanoseconds. Default `60000000000` (1 minute). |
| `max_pages` | no | Caps pages fetched per poll. Default `20` (10,000 signals at the default `limit`). |
| `dedupe_ttl` | no | How long a signal id is remembered to suppress re-shipping. Default 7 days. |
| `retry_base_delay` / `max_retry_delay` / `max_retry_attempts` | no | Transient-failure retry tuning. |

## How polling works

Huntress paginates Signals with an opaque `page_token` cursor (see the
[pagination docs](https://api.huntress.io/docs#pagination)); there is no
"created after X" filter to resume from. The adapter sorts newest-first
(`sort_field=id&sort_direction=desc`, the API's own default) and, on every
poll, walks pages from the start — page 1 always holds the newest signals —
until a short page is returned, `pagination.next_page_token` is absent, or
`max_pages` is reached.

Because every poll re-walks the newest pages rather than resuming from a
persisted cursor, an in-memory deduper (keyed on the Signal `id`) guarantees
each signal still ships to LimaCharlie exactly once. This also makes the
adapter restart-safe with no state to persist: after a restart, the next poll
simply re-fetches the newest signals and the deduper absorbs the overlap.

For a very high signal volume, bound each poll's work with `max_pages` and
`limit` comfortably above the expected per-interval volume; the adapter warns
when a poll hits the `max_pages` cap, meaning older signals were not walked
that round (they are typically age out into `max_pages*limit` coverage on a
later poll as newer signals push them further back — narrow `types`/`statuses`
or shorten `poll_interval` if this warning appears often).

Huntress rate-limits each account to 60 requests/minute (sliding window).
HTTP 429 and 5xx responses are retried with exponential backoff. HTTP 401/403
(rejected credentials) stops the adapter, since no amount of retrying can fix
a bad key/secret pair; fix the credentials and restart the adapter. Other
4xx errors (e.g. an unknown `organization_id`) are logged as a warning and
only abandon that poll — the adapter keeps running and retries on the next
interval.

## Examples

Via the CLI:

```
./general huntress \
  client_options.identity.oid=$OID \
  client_options.identity.installation_key=$INSTALLATION_KEY \
  client_options.platform=json \
  client_options.sensor_seed_key=huntress \
  api_key=$HUNTRESS_API_KEY \
  api_secret=$HUNTRESS_API_SECRET
```

Via a YAML config file, scoped to one organization and two Signal types:

```yaml
huntress:
  client_options:
    identity:
      oid: $OID
      installation_key: $INSTALLATION_KEY
    platform: json
    sensor_seed_key: huntress
  api_key: $HUNTRESS_API_KEY
  api_secret: $HUNTRESS_API_SECRET
  organization_id: 232
  types:
    - Antivirus
    - Footholds
```

## Testing note

This adapter's mock/fake test suite (`mock_test.go`) is built from the
documented API shapes (the published OpenAPI spec and support docs) and has
**not** been live-verified against a real Huntress account. If you hit an
unexpected shape or pagination behavior against a live account, please open
an issue or PR.
