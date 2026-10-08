# API reference

Interactive OpenAPI docs are served by the running API:

- Swagger UI: `${PUBLIC_URL}/api/docs`
- ReDoc: `${PUBLIC_URL}/api/redoc`
- Schema: `${PUBLIC_URL}/api/openapi.json`

(Direct, without the proxy: `http://localhost:8000/docs`.)

Auth: obtain a token from `POST /auth/login`, then send
`Authorization: Bearer <token>` (or `X-API-Key: <key>` for an API key).

## Endpoint groups

| Group | Key endpoints |
|-------|---------------|
| auth | `POST /auth/login`, `/auth/refresh`, `GET /auth/me`, MFA setup/enable, API keys |
| users | `GET/POST /users`, `PATCH/DELETE /users/{id}` |
| targets | `GET/POST /targets`, `GET/PATCH/DELETE /targets/{id}` |
| authorization | `GET/POST /targets/{id}/authorizations`, `/{aid}/status`, `/{aid}/revoke` |
| credentials | `GET/POST /targets/{id}/credentials`, `DELETE …/{cid}` (secrets never returned) |
| scans | `POST /targets/{id}/scan`, `GET /scans`, `GET /scans/{id}`, `/cancel`, `/rescan` |
| inventory | `GET /targets/{id}/{wordpress,plugins,themes,wp-users,assets,technologies,changes}` |
| findings | `GET /findings`, `GET /findings/{id}`, `PATCH …/status`, `GET …/evidence`, `GET/POST …/verify`, `…/verification` |
| vulnerabilities | `GET/POST /vulnerabilities`, `GET /vulnerabilities/{id}` |
| pocs | `GET/POST /pocs`, `GET/PATCH /pocs/{id}`, `GET /pocs/sources`, `POST /pocs/sync` |
| reports | `POST /scans/{id}/report`, `POST /targets/{id}/report`, `GET /reports`, `GET /reports/{id}`, `/download` |
| labs | `GET/POST /labs`, `GET/POST /labs/{id}/instances`, `DELETE /labs/instances/{id}` |
| schedules | `GET /schedules`, `POST /targets/{id}/schedules`, `DELETE /schedules/{id}` |
| workers | `GET /workers` |
| dashboard | `GET /dashboard/stats` |
| audit | `GET /audit` |
| health | `GET /health`, `GET /health/detailed` |

## Example: add → authorize → audit → report

```bash
TOKEN=$(curl -s $API/auth/login -H 'content-type: application/json' \
  -d '{"email":"admin@example.com","password":"…"}' | jq -r .access_token)
auth() { curl -s -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' "$@"; }

TID=$(auth $API/targets -d '{"name":"Site","base_url":"https://site.example"}' | jq -r .id)
AID=$(auth $API/targets/$TID/authorizations \
  -d '{"auth_type":"written_consent","authorized_by":"me","allowed_scope":["site.example"],"expiration_date":"2026-12-31T23:59:59+00:00"}' | jq -r .id)
auth $API/targets/$TID/authorizations/$AID/status -d '{"status":"active"}' >/dev/null
SID=$(auth $API/targets/$TID/scan -d '{"profile":"standard"}' | jq -r .id)
auth $API/findings?scan_id=$SID | jq '.[].title'
REP=$(auth $API/scans/$SID/report -d '{"report_format":"html"}' | jq -r .id)
curl -s -H "authorization: Bearer $TOKEN" $API/reports/$REP/download -o report.html
```

All mutating calls are recorded in the audit log.
