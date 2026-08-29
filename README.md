# lex-attest

**A hash chain and signature verification over HTTP, for systems that are not written in Lex.**

`lex-trail` and `lex-device-identity` are Lex libraries: to use them you write Lex. This wraps them in JSON so a service in any language can append to an evidence chain, walk it, and verify a signed reading — and find out whether that is worth anything before adopting a line of Lex.

```bash
ATTEST_KEY=trial-key DB_PATH=./attest.db PORT=8090 \
  lex run --allow-effects net,io,time,env,sql,fs_read,fs_write,concurrent,random,crypto,llm,proc,approval \
  src/server.lex main
```

Needs `lex` on your PATH — a [release binary](https://github.com/alpibrusl/lex-lang/releases) is enough. Dependencies fetch on first run.

## What it does not do

It holds one database of its own, answers questions about that database, and **never reaches into your systems**. No agent, no polling, no callbacks, no schema in your database. You send it events you already have; it gives you ids you can store beside your own records, or throw away.

That is the point. The cost of trying it is one process and one env var, and the cost of abandoning it is deleting a file.

## The four calls

```bash
# append — returns the event with its content-addressed id
curl -X POST localhost:8090/v1/events -H 'Authorization: Bearer trial-key' \
  -d '{"kind":"meter.reading","payload":{"cp":"cp-04","register_wh":105500}}'
# {"id":"bcef42d5…","kind":"meter.reading","parent":null,"payload":"{…}","ts_ms":1788015111682}

# link a second event to the first
curl -X POST localhost:8090/v1/events -H 'Authorization: Bearer trial-key' \
  -d '{"kind":"settlement.energy","parent":"bcef42d5…","payload":{"eur_cents":1064}}'

# walk from any event back to the root of its chain
curl localhost:8090/v1/events/1b67c9c0…/chain -H 'Authorization: Bearer trial-key'
# [{"kind":"settlement.energy",…},{"kind":"meter.reading",…}]

# was this reading signed by the device that claims it?
curl -X POST localhost:8090/v1/verify -H 'Authorization: Bearer trial-key' \
  -d '{"cert":"…","body":"…","signature":"…","platform_public_key":"…"}'
# {"verified":true}   or   {"verified":false,"reason":"…"}
```

`GET /health` is unauthenticated. Everything else needs the bearer token.

## The id is the content

An event's `id` is the SHA-256 of its kind, parent, payload and timestamp. The same logical event produces the same id wherever it is materialised, so two parties who computed it independently can compare one string instead of diffing records. That is also why `payload` travels as a JSON *value* rather than a pre-encoded string — the service canonicalises it, so two callers sending the same object land on the same id.

## Configuration

| variable | |
|---|---|
| `ATTEST_KEY` | bearer token. **Required** — unset means everything but `/health` is refused |
| `DB_PATH` | SQLite file, default `./attest.db` |
| `DB_URL` | Postgres URL; takes precedence over `DB_PATH` |
| `PORT` | default `8090` |

**Fail-closed on purpose.** With no `ATTEST_KEY` the service starts, says so on stdout, and refuses every write. A trial deployment that quietly accepted anonymous appends would be building an evidence chain anyone could write to — worse than no chain, because it looks like provenance.

## What this establishes, and what it doesn't

**Established.** That an event with this id had this content at this time, that it links to that parent, and — for `/v1/verify` — that a reading was signed by the key in a certificate the platform issued.

**Not established.** That the content is *true*. A hash chain records what you told it, in an order that cannot be quietly rearranged. If you feed it a wrong number, you get a wrong number nobody can silently change afterwards. That is genuinely useful and it is not the same as verification of fact.

## License

Copyright (c) 2026 lex-attest contributors.

Licensed under the [EUPL-1.2](LICENSE) — the European Union Public Licence, as used across the `lex-*` ecosystem.
