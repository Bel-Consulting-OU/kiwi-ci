# Runs collection API

`GET /api/v1/runs` lists the runs visible to the caller, newest first, as a
keyset-paginated collection. Every run is reachable, including runs older
than the first page, and the pagination stays stable while new runs are
being created.

The endpoint is the same collection read as before: the response body is an
unchanged JSON array of run objects, and the default page is still the
newest 1000 runs. Pagination is additive — clients that ignore the new
parameters and the cursor header keep working, and clients that follow the
cursor can walk the whole history.

## Request

`GET /api/v1/runs?limit=<n>&cursor=<opaque>`

| Parameter | Default | Bound | Meaning |
| --- | --- | --- | --- |
| `limit` | `1000` | `1`..`10000` | Maximum runs in one page. Absent, unparsable, or non-positive values select the default; values above the cap are clamped to the cap. The effective bound is advertised on every response as `X-Kiwi-Runs-Limit-Cap`. |
| `cursor` | *(empty)* | opaque | Position returned by the previous page (`X-Kiwi-Next-Cursor` header). Omit it (or pass it empty) for the newest page. A malformed cursor is rejected with `400 Bad Request` and the opaque body `invalid cursor`; the value is never echoed or interpreted beyond the cursor encoding. |

The collection is gated by the coarse read gate (admin/global read, or any
repository read grant); a reader without any read capability is answered
`403`, not an empty `200`. The gate is not the per-run decision: the
principal's normalized repository-read predicate is resolved once per request
(`runAuthzPolicy`) and applied **inside** the paged query, before the page
boundary exists, so no returned row, count, timestamp or cursor is ever
derived from a run the caller cannot read.

## Response

`200 OK` with the unchanged JSON array of run objects, ordered
`created_at DESC, id DESC` (newest first; `id` breaks `created_at` ties so
the order is total).

Two response headers carry the pagination state:

| Header | Present | Meaning |
| --- | --- | --- |
| `X-Kiwi-Next-Cursor` | Exactly when more authorized runs exist after the returned page | Pass this value back verbatim as `cursor` to fetch the next, older page. It is derived from the last returned run and omitted on the last (or an empty) authorized page, so the walk terminates when the header is absent. |
| `X-Kiwi-Runs-Limit-Cap` | On every `200` response | The hard per-page cap (`10000`). |

## Cursor format

The cursor is opaque: clients must treat it as an uninterpreted token and
pass it back exactly as received. For context, it is versioned and encoded
in the same structured-key style already used elsewhere in the repository
(a version prefix plus raw-URL base64 of a JSON array):

```
rk1:<base64url(["<created_at RFC3339Nano, UTC>", "<run id>"])>
```

The version prefix is part of the format; a future change of the position
encoding would bump it, and an unparsable cursor is always rejected with the
opaque `400`.

## Pagination contract

- **Ordering.** Pages are consecutive windows of one total order,
  `(created_at DESC, id DESC)`. The first page is the newest `limit` runs.
- **Keyset, not offsets.** A page contains only runs strictly older than the
  cursor position `(created_at, id)`. A run created between two page reads is
  newer than the cursor and is simply not part of the remaining walk of that
  traversal (a fresh first-page request sees it); it can never shift a page
  boundary, so a walk never returns a run twice and never skips one.
- **Authorization happens before paging.** The principal's normalized
  repository-read predicate is a clause of the same query that computes the
  keyset boundary, so the page is cut from the authorized rows alone. The
  next cursor is derived from the last returned run's `(created_at, id)` —
  never from the global collection and never from how many runs survived a
  filter. A repository-scoped reader therefore sees only pages of visible
  runs, and can never observe the position, count or density of an
  inaccessible run.
- **Terminal empty pages carry no cursor.** Because the boundary is computed
  on authorized rows, an empty authorized page is the end of the walk: it is
  answered `200` with an empty JSON array and no `X-Kiwi-Next-Cursor`.
  Following `X-Kiwi-Next-Cursor` until it is absent reaches every authorized
  run exactly once; each page advances the cursor strictly through
  `(created_at, id)`, so the walk is bounded by the number of authorized runs.
  Filtering can never create a false "last page" gap that hides older runs
  from an authorized reader.

## Store capability

The server serves paged run collections only from stores that implement the
authorized keyset interface `storage.RunPageAuthorizedStore`; both stores
shipped with Kiwi (memory and PostgreSQL) do. `RunPageAuthorizedStore` is
deliberately separate from the older unfiltered `storage.RunPageStore`: paging
the global collection and filtering afterwards would leak the page boundary,
so the server never falls back to `RunPageStore`. A custom `storage.Store`
that cannot apply the principal's repository predicate inside the page query
therefore fails closed with an opaque `500` body (`internal server error`)
instead of a truncated or boundary-leaking `200`. The diagnostic detail,
`authorized runs pagination unsupported by configured store`, is logged
server-side and never returned to the client.

The bundled dashboard follows the cursor through its **Load older runs**
control: each click appends exactly one page using the previous
`X-Kiwi-Next-Cursor` value, and the control disappears when the last page
carries no cursor. It never walks the remaining pages on its own.

## Example

```sh
# First page: the newest 100 runs.
curl -si -H "Authorization: Bearer $KIWI_TOKEN" \
  'https://kiwi.example.com/api/v1/runs?limit=100'

# Follow the returned cursor to the next, older page.
curl -si -H "Authorization: Bearer $KIWI_TOKEN" \
  'https://kiwi.example.com/api/v1/runs?limit=100&cursor=rk1:...'

# Reducing the page size is allowed.
curl -si -H "Authorization: Bearer $KIWI_TOKEN" \
  'https://kiwi.example.com/api/v1/runs?limit=25'

# Values above the cap are clamped, not an error.
curl -si -H "Authorization: Bearer $KIWI_TOKEN" \
  'https://kiwi.example.com/api/v1/runs?limit=999999'
```
