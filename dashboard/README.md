# Korvyr dashboard

A small React viewer for the npm proxy's decision log. It polls
`GET /api/logs` on the proxy every two seconds and renders the recorded
verdicts. It is a read-only view: it cannot scan, block, or configure anything.

## Run it

```bash
cd dashboard
npm install
npm run dev          # http://localhost:5173
```

The proxy must be running (default `http://localhost:4873`). To point the
dashboard elsewhere:

```bash
VITE_KORVYR_PROXY_URL=http://localhost:5873 npm run dev
```

## Notes

- The proxy serves its log from `proxy/logs.jsonl`; entries appear only after a
  package has been fetched through the proxy.
- The `GNN score` column shows `-` when the scanner ran in static-only mode.
- `npm run lint` runs ESLint over the dashboard sources.
