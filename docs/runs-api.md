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

Authorization is unchanged: the collection is gated by the coarse read gate
(admin/global read, or any repository read grant), and every run in a page is
then filtered individually through the repository-grant resolution. A reader
without any read capability is answered `403`, not an empty `200`.

## Response

`200 OK` with the unchanged JSON array of run objects, ordered
`created_at DESC, id DESC` (newest first; `id` breaks `created_at` ties so
the order is total).

Two response headers carry the pagination state:

| Header | Present | Meaning |
| --- | --- | --- |
| `X-Kiwi-Next-Cursor` | Exactly when more runs exist after the returned page | Pass this value back verbatim as `cursor` to fetch the next, older page. It is omitted on the last page, so the walk terminates when the header is absent. |
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
- **RBAC filtering happens after paging.** The page is cut from the store
  first, then each run is filtered through the repository grants, and the
  next cursor is derived from the page boundary the store returned — never
  from how many runs survived the filter. A page can therefore contain fewer
  visible runs, or even be an empty array, while still carrying
  `X-Kiwi-Next-Cursor`; following it reaches the older visible runs, and the
  walk terminates when a page reports no further rows. Filtering can never
  create a false "last page" gap that hides older runs from an authorized
  reader.
- **Termination.** Follow `X-Kiwi-Next-Cursor` until it is absent. Each page
  advances the cursor strictly through `(created_at, id)`, so the walk is
  bounded by the number of underlying runs.

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
