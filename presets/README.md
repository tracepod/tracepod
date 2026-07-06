# Runtime presets

Curated include-path sets for files a runtime **needs but the profiler cannot
observe**: work directories created at startup (nginx's cache tree, Apache's
pid dir), paths the denylist deliberately drops from profiles (`/tmp`, `/run`,
`*.log`), and interpreter files that are stat()ed but never opened.

Each preset is a JSON document:

```json
{
  "name": "runtime-nginx",
  "description": "why these paths are invisible to profiling",
  "paths": [{ "path": "/var/log/nginx", "type": "directory" }]
}
```

`type` is `directory` (created empty in the hardened image and expanded from
the source image when present) or `file` (created as an empty file when absent).

Use with the CLI (`harden build --include/--mkdir/--touch`) or via the
Tracepod dashboard, which ships these presets built-in and auto-suggests the
matching one per workload.

**Contributions welcome.** The bar for a new preset or path: a runtime that
fails or degrades without it, with the failure mode in the description —
these are curated known gaps, not kitchen-sink includes.
