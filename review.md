# Passive HTTP Traffic Security Review

**Source:** `req.txt` (Burp Suite XML export, Burp 2026.8)

**Target host observed:** `knowledgehub.sims-vapt-test.digatex.com`

**Review mode:** Passive review of the supplied capture only. No requests were sent to the target.

**Redaction:** Bearer tokens, session-cookie values, email addresses, and resource identifiers are omitted or replaced with placeholders below.

## 1. Traffic Summary

- **Requests reviewed:** 155 request/response items; the XML parsed successfully. No request or response was base64-encoded and no NULL bytes were present in the file.
- **Observed period:** 6–7 October 2026 (IST).
- **Hosts:** One host, `knowledgehub.sims-vapt-test.digatex.com`.
- **Methods:** GET 120, POST 28, PUT 6, DELETE 1. No PATCH or OPTIONS requests were captured.
- **Responses:** 200: 143; 304: 6; 307: 1; 301: 1; 500: 4. No 401, 403, 404, or 429 responses were captured.
- **Endpoint inventory:** 74 method/route combinations across 72 normalized path templates. Path IDs below are normalized as `{id}` and the export-job identifier as `{job_id}`. Query/body values are intentionally omitted; parameter names are inventoried below.
- **Authentication:** `Authorization: Bearer [REDACTED_TOKEN]` appeared in 132 requests. The API requests returning JSON data in this capture used Bearer authentication; the one API-root request without it returned only a redirect. No Basic Auth or API-key header was observed. No access token was present in a URL.
- **JWT observations:** 24 distinct bearer tokens were present. All decoded headers used `RS256`; each token contained `iat`, `exp`, `iss`, `aud`, and `sub`, with a 300-second `exp - iat` interval. This is positive evidence for short-lived, signed tokens, but signatures/key management cannot be independently validated from this export. The tokens also contain identity/role claims and must be treated as sensitive.
- **Cookies:** `view_workspace_id` appeared in 148 requests. `AUTH_SESSION_ID` and `AUTH_SESSION_ID_LEGACY` appeared once each. These values are not reproduced. No `Set-Cookie` response header was captured, so Secure/HttpOnly/SameSite attributes and session rotation cannot be assessed.
- **Security headers:** All 155 responses included CSP, HSTS (`max-age=31536000; includeSubDomains; preload`), `X-Content-Type-Options: nosniff`, `X-Frame-Options`, and `Referrer-Policy`. No `Server` or `X-Powered-By` banner was observed. API responses used `Cache-Control: no-store`; the `public, max-age=15` responses were page shells/static resources.
- **CORS:** 31 responses included `Access-Control-Allow-Credentials: true`, but no response included `Access-Control-Allow-Origin`. No wildcard or reflected allowed origin was observed; the credentials header by itself does not establish exploitable CORS access.
- **Static configuration:** `/runtime-config.js` exposes client-side URLs, Keycloak client/realm configuration, and a reCAPTCHA site key. These are browser-visible configuration values; no private key or server-side API secret was identified in that response.
- **Capture-handling alert (not a target finding):** `req.txt` contains raw Bearer tokens, two auth-session cookie values, an account email, and project/document metadata. They are redacted in this report. Treat the capture as sensitive; invalidate/revoke any still-live sessions and sanitize it before further sharing.

### Endpoint and parameter inventory

The endpoint list is normalized: distinct resource IDs are represented as placeholders. “Query” lists URL query parameter names; “Body” lists observed JSON keys (selected nested keys are shown in parentheses). Standard browser headers are not repeated here.

#### API endpoints

| Method | Endpoint | Query parameters | JSON body parameters |
|---|---|---|---|
| GET | `/api/v1` | — | — |
| GET | `/api/v1/comments/assign_targets` | `is_final`, `result_id` | — |
| GET | `/api/v1/comments/by_page` | `is_final`, `page_id`, `result_id` | — |
| GET | `/api/v1/get_current_user` | — | — |
| GET | `/api/v1/hierarchies` | `workspace_id` | — |
| GET | `/api/v1/hierarchies/export_hierarchy/reports` | — | — |
| GET | `/api/v1/hierarchies/filtered` | `limit`, `page`, `search`, `use_wildcards` | — |
| GET | `/api/v1/hierarchies/{id}/is_in_scope` | `page_id` | — |
| GET | `/api/v1/hierarchies/{id}/logs/for_user` | `limit`, `page`, `show_all` | — |
| GET | `/api/v1/hierarchies/{id}/nodes/{id}/references/{id}/tag_reference` | — | — |
| GET | `/api/v1/hierarchies/{id}/nodes/{id}/uniqueness_violating_attributes` | — | — |
| GET | `/api/v1/hierarchies/{id}/system_attributes` | — | — |
| GET | `/api/v1/projects/{id}` | — | — |
| GET | `/api/v1/projects/{id}/final_results/{id}` | — | — |
| GET | `/api/v1/projects/{id}/final_results/{id}/logs` | — | — |
| GET | `/api/v1/projects/{id}/final_results/{id}/source_run` | — | — |
| GET | `/api/v1/projects/{id}/get_page_thumbnail_batched` | `batch_size`, `is_final`, `page_number`, `result_id`, `total` | — |
| GET | `/api/v1/projects/{id}/processing_runs/{id}` | — | — |
| GET | `/api/v1/projects/{id}/processing_runs/{id}/results/{id}` | — | — |
| GET | `/api/v1/projects/{id}/processing_runs/{id}/results/{id}/final_result` | — | — |
| GET | `/api/v1/projects/{id}/settings` | — | — |
| GET | `/api/v1/user_view/export_tags/progress/{job_id}` | — | — |
| GET | `/api/v1/user_view/export_tags/reports` | — | — |
| GET | `/api/v1/user_view/final_results` | `limit`, `page`, `search` | — |
| GET | `/api/v1/user_view/final_results/count` | — | — |
| GET | `/api/v1/user_view/runs` | — | — |
| GET | `/api/v1/user_view/runs/{id}` | — | — |
| GET | `/api/v1/user_view/runs/{id}/total_drawings` | — | — |
| GET | `/api/v1/user_view/search_filters_configs` | — | — |
| GET | `/api/v1/user_view/search_results/possible_search_option_keys` | `max_results`, `option_target`, `option_value_part` | — |
| GET | `/api/v1/user_view/search_results/possible_search_option_values` | `max_results`, `option_key`, `option_target`, `option_value_part` | — |
| GET | `/api/v1/workspaces` | `all` | — |
| GET | `/api/v1/workspaces/{id}` | — | — |
| GET | `/api/v1/workspaces/{id}/comment_system_attributes` | — | — |
| GET | `/api/v1/workspaces/{id}/default_search_customize_config` | — | — |
| GET | `/api/v1/workspaces/{id}/excel_reports_configs` | — | — |
| GET | `/api/v1/workspaces/{id}/feature_flags` | — | — |
| GET | `/api/v1/workspaces/{id}/post_processing_lambda_functions` | — | — |
| GET | `/api/v1/workspaces/{id}/system_attributes` | — | — |
| POST | `/api/v1/all_results/drawing_versions` | — | `result_reference` (`result_id`, `is_final`) |
| POST | `/api/v1/all_results/get_annotation_object` | — | `tag_reference` (`tag_number`, `tag_id`, `result_reference`) |
| POST | `/api/v1/all_results/hierarchy_node_attributes` | `hierarchy_id` | `result_reference` (`result_id`, `is_final`) |
| POST | `/api/v1/comments` | `is_final`, `page_id`, `result_id` | `message`, `author`, `date`, `markers`, `replies`, `groups`, `attributes`, `status`, `assign_targets`, `markup` |
| POST | `/api/v1/comments/{id}/replies` | — | `message`, `user_id` |
| POST | `/api/v1/feedback/contact_us` | — | `email`, `message`, `name`, `phone`, `recaptcha_token` |
| POST | `/api/v1/hierarchies/{id}/nodes/filtered` | `limit`, `page`, `query` | `filters` |
| POST | `/api/v1/hierarchies/{id}/partial_loading/load_nodes` | — | `tags_list` (including `text`, `label`, `full_load`) |
| POST | `/api/v1/user_view/comments` | `for_you`, `limit`, `page`, `search`, `show_mode`, `status`, `use_wildcards` | `filters` |
| POST | `/api/v1/user_view/drawings_to_compare` | — | `filters`, `pagination`, `result_reference` (including `limit`, `page`, `operation`, `key`, `value`, `target`) |
| POST | `/api/v1/user_view/drawings_to_compare/filter_values` | — | `result_reference` (`result_id`, `is_final`) |
| POST | `/api/v1/user_view/export_tags` | — | `columns_config_id`, `export_final_results`, `filters`, `run_id`, `use_final_if_possible` |
| POST | `/api/v1/user_view/runs/{id}/search_results` | `ignore_text_objects`, `limit`, `page`, `search`, `show_mode`, `use_wildcards` | `filters`, `custom_columns` (`name`, `target`) |
| POST | `/api/v1/user_view/search_results` | `ignore_text_objects`, `limit`, `page`, `search`, `show_mode`, `use_wildcards` | `filters`, `custom_columns` (`name`, `target`) |
| PUT | `/api/v1/projects/{id}/final_results/{id}` | — | `annotation` (including `details`, `fields`, `image_id`, `objects`, `workpacks`) |
| PUT | `/api/v1/workspaces/{id}/excel_reports_configs/{id}` | — | `id`, `name`, `unique_tags`, `columns` (`name`, `value`, `value_type`), `labels_to_ignore`, `post_processing_lambda_id` |
| DELETE | `/api/v1/projects/{id}/final_results/{id}` | — | — |

#### Web UI, static assets, and client-side routes

| Method | Endpoint | Query parameters |
|---|---|---|
| GET | `/` | — |
| GET | `/index` | — |
| GET | `/assets/index-B1A0LBoV.css` | — |
| GET | `/assets/index-BoNb8hHv.js` | — |
| GET | `/images/export-to-pdf.svg` | — |
| GET | `/images/filter_list-24px.svg` | — |
| GET | `/images/split-mode-horizontal.svg` | — |
| GET | `/project/{id}/explore_results/{id}/view_document/{id}` | `comment_id` |
| GET | `/project/{id}/final_results/view_result/{id}` | `comment_id`, `hierarchy_id` |
| GET | `/robots.txt` | — |
| GET | `/runtime-config.js` | — |
| GET | `/runtime-theme.css` | — |
| GET | `/user_view/comments` | — |
| GET | `/user_view/configure_reports` | — |
| GET | `/user_view/explore_results` | — |
| GET | `/user_view/explore_results/{id}` | — |
| GET | `/user_view/finalize_results` | — |
| GET | `/user_view/search` | `ignoreTextObjects`, `page`, `q`, `showMode`, `tab`, `useWildcards` |

## 2. Findings Table

| # | Finding | Severity | OWASP Category | CWE | Status |
|---|---|---|---|---|---|
| F-01 | HTTPS API-root request redirects to an HTTP URL | Low — CVSS 3.1 **2.4** (conditional impact) | OWASP A05:2021 Security Misconfiguration; API8:2023 Security Misconfiguration | CWE-319 | Confirmed configuration weakness; sensitive-data impact not demonstrated |
| F-02 | User-controlled HTML-like comment content is persisted and returned; unsafe rendering is unverified | Medium — provisional CVSS 3.1 **4.9** if an unsafe cross-user HTML sink exists | OWASP A03:2021 Injection | CWE-79 | Potential — requires UI/output-context validation |

## 3. Detailed Findings

### F-01 — HTTPS API-root request redirects to an HTTP URL

- **Severity + CVSS:** Low, **2.4** — `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N`. The score assumes a non-HSTS client follows the downgrade and later sends low-sensitivity data; that consequence was not observed. HSTS reduces browser exposure.
- **Affected endpoint:** `GET /api/v1`.
- **Evidence (Burp item 2):**

  ```http
  GET /api/v1 HTTP/2
  Host: knowledgehub.sims-vapt-test.digatex.com

  HTTP/2 307 Temporary Redirect
  Location: http://knowledgehub.sims-vapt-test.digatex.com/api/v1/
  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
  Content-Length: 0
  ```

- **Explanation:** An HTTPS request receives a redirect whose `Location` explicitly downgrades to HTTP. HSTS is also present and should cause compliant browsers to upgrade, but arbitrary API clients and integrations may not enforce HSTS. The captured request had no Authorization header and the redirect response had no body; therefore this capture does **not** prove that credentials or data were actually transmitted over HTTP.
- **Impact:** If a client follows the redirect without HSTS and then sends sensitive requests over HTTP, an on-path attacker could observe or modify that traffic.
- **Recommendation:** Return an absolute HTTPS `Location` (or a relative path), correct reverse-proxy scheme/forwarded-proto handling, and enforce HTTPS at the edge for all API routes. Verify that no redirect target uses `http://`.

### F-02 — Stored HTML-like content is returned by APIs; XSS execution is not proven

- **Severity + CVSS:** **Medium, provisional 4.9** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`, **only if** a different user's browser renders this stored value as executable HTML. This vector is conditional, not a confirmed score for the observed behavior.
- **Affected endpoints:** `POST /api/v1/comments/{id}/replies`, `GET /api/v1/comments/by_page`; similar HTML-like strings also appear in hierarchy and annotation data returned by `GET /api/v1/hierarchies`, `GET /api/v1/hierarchies/filtered`, `GET /api/v1/hierarchies/export_hierarchy/reports`, and `GET /api/v1/projects/{id}/final_results/{id}`.
- **Evidence (Burp item 84; values redacted where identifying):**

  ```http
  POST /api/v1/comments/{id}/replies
  Authorization: Bearer [REDACTED_TOKEN]
  Content-Type: application/json

  {"message":"\"><script>alert(1)</script>","user_id":"[REDACTED_USER_ID]"}

  HTTP/2 200 OK
  Content-Type: application/json
  X-Content-Type-Options: nosniff

  Response JSON path replies[216].message:
  "\"><script>alert(1)</script>"
  ```

  A separate authenticated hierarchy-list response also contains a stored name value equivalent to `"<script>alert(10)</script>"`.

- **Explanation:** The API accepts and returns HTML/script-like data in a comment string and returns comparable values in hierarchy/annotation fields. This confirms storage/return of the string, **not** browser execution. Responses are JSON, `nosniff` is set, and CSP is present; the capture contains no resulting HTML page, DOM context, or execution evidence. A React/text-safe rendering path would not be vulnerable merely because the JSON contains a script string.
- **Impact:** If the UI inserts these fields into an HTML sink without contextual encoding/sanitization, another user viewing the comment/result/hierarchy could be exposed to stored XSS in the application origin.
- **Recommendation:** Render these fields as text nodes and apply context-appropriate output encoding. If rich text is required, sanitize with a strict allowlist. Validate the affected comment, hierarchy, and annotation views using a harmless marker and a second authorized test account; do not treat JSON reflection alone as proof of XSS.

## 4. Gaps / What I Couldn't Determine

1. **Authorization/BOLA and actor binding:** All observed authenticated API traffic belongs to one JWT subject/account. Resource IDs appear in paths and bodies, but no second user's or tenant's token was supplied. The reply-creation request includes a client-supplied `user_id` equal to the authenticated subject; the capture cannot show whether the server derives or validates it. No BOLA/IDOR/BFLA or author-spoofing finding can be confirmed. A second role/tenant capture and a controlled actor-binding check are needed.
2. **Cross-service JWT roles:** The decoded bearer claims include seven audiences and resource roles with names such as `workbench-api-superadmin`, `inventory-api: admin`, and `adv-dm-admin`; the Knowledge Hub `/api/v1/get_current_user` response reports `roles: ["user"]` and the token also has a Knowledge Hub user role. This may be intentional service-specific authorization. No calls to the sibling services or role matrix were provided, so this is **not** reported as privilege escalation. Confirm that the cross-service role grants are intended and that the UI token is least-privileged.
3. **SQLi and other injection:** The capture includes SQL/time-delay, XML/OAST, command, template, path-traversal, and XSS-like strings in stored comment/report/configuration data. They are returned as data; no database error detail, measured delay, command output, outbound callback, file read, or template evaluation is evidenced. A report-configuration PUT containing `Tag type'.sleep(20).'` returned 200 and echoed the value; this alone does not establish SQL injection. A quote-query request to `/api/v1/hierarchies/{id}/nodes/filtered` returned 500, but the same endpoint with an empty query also returned 500, and both responses were generic `Internal Server Error` text.
4. **Other 500 responses:** Four API requests returned generic 500 errors (`POST /api/v1/comments`, `POST /api/v1/feedback/contact_us`, and two `POST /api/v1/hierarchies/{id}/nodes/filtered` requests). No stack trace or detailed exception was disclosed. The cause and availability impact cannot be determined from these responses.
5. **Rate limiting:** No login, OTP, password-reset, or token-issuance flow was captured; no sustained rate test was performed. The absence of 429 responses in this dataset does not demonstrate absent throttling.
6. **Session cookie flags:** No `Set-Cookie` header was present in the 155 responses, so Secure, HttpOnly, SameSite, expiry, and rotation behavior cannot be assessed. The request capture contains workspace-selection and auth-session cookie names, but not their issuing responses.
7. **Excessive data exposure:** Authenticated responses include account/project metadata, document annotations, and a large comment thread. The capture does not include the UI field requirements or another user's access, so it cannot establish that the returned fields exceed what the authorized UI needs. Some configuration-list responses are large; pagination/limits should be reviewed for scale, but no resource-exhaustion behavior is shown.
8. **CORS, TLS, and inventory:** No permissive `Access-Control-Allow-Origin` was observed. The export does not reveal TLS certificate/protocol settings, server-side configuration, the API specification, or whether any observed route is undocumented/shadow inventory.
9. **Capture sensitivity:** Raw short-lived Bearer JWTs, auth-session cookie values, account identity, and potentially proprietary engineering metadata are present in `req.txt`. This is an assessment-artifact handling concern, not evidence that the application leaked those values to an unauthenticated party.

## 5. Next Steps

1. **Fix/verify the HTTPS redirect:** Manually check `/api/v1` and related slash-normalization paths with browser and non-browser clients; ensure every redirect remains HTTPS and verify proxy headers.
2. **Validate stored XSS safely:** In an authorized test tenant, add a harmless unique marker to comment, hierarchy, report-name, and annotation fields, then inspect the rendered DOM under a second test account. Confirm text-node rendering or sanitizer behavior and CSP enforcement.
3. **Validate injection candidates separately:** Use controlled, non-destructive paired tests (baseline versus input) on the exact search/configuration/comment fields. Compare status, response, and timing under a bounded test plan. Do not infer execution from a stored payload or generic 500. Use approved out-of-band validation only if in scope.
4. **Test authorization with multiple roles/tenants:** Replay representative project, final-result, hierarchy, comment, export, and workspace requests using an authorized second principal and resources outside its scope. Expect deny-by-default 403/404 behavior and verify object ownership on every operation.
5. **Review service-specific JWT entitlements:** Compare the observed cross-service roles to the account's approved role matrix; restrict audiences/claims where appropriate and test each service only with authorization.
6. **Check session/rate-limit controls:** Capture login/logout/token refresh and `Set-Cookie` responses; separately test throttling/lockout for authentication and sensitive export/search operations.
7. **Review large collection behavior:** Confirm pagination and response-size limits for report-configuration and comment-history endpoints if those collections can grow in production.
8. **Protect the capture:** Revoke any still-live captured sessions/tokens, replace the raw capture with a redacted copy before distribution, and restrict access to any retained original.

---

**Conclusion:** One confirmed transport-configuration weakness (HTTP downgrade redirect) and one potential stored-XSS candidate are supported by the capture. No SQLi, command injection, SSRF, XXE, path traversal, authorization bypass, CORS bypass, or rate-limit flaw is confirmed from the available evidence.
