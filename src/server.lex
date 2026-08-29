# lex-attest — the sidecar.
#
#   POST /v1/events            append {kind, parent?, payload} -> the event, with its id
#   GET  /v1/events/:id/chain  walk from an event to the root of its chain
#   GET  /v1/events            everything in a time window
#   POST /v1/verify            check a signed reading against its device certificate
#   POST /v1/anchors           commit to everything up to now — publish this elsewhere
#   POST /v1/anchors/verify    does this log still reproduce an anchor you hold?
#   GET  /health               liveness, unauthenticated
#
# Configuration:
#   ATTEST_KEY  bearer token. REQUIRED — unset means everything but /health is refused.
#   DB_PATH     SQLite file (default ./attest.db), or DB_URL for Postgres
#   PORT        default 8090
#
# Anchors are why this can be run BY someone other than the party relying on
# it. Everything else here is only as trustworthy as whoever holds the
# database: they could delete an event nobody kept the id of, or rewrite the
# lot and recompute every id so it stays internally coherent. An anchor is a
# small commitment the caller takes away and keeps — or publishes somewhere the
# holder does not control. Afterwards the holder can still change the data;
# they cannot make the anchor reproduce.
#
# The point of this service is what it does NOT do. It holds one database of
# its own, it answers questions about that database, and it never reaches into
# the caller's systems. A team can put it beside an existing stack, send it the
# events they already have, and find out whether a hash chain is worth anything
# to them before adopting a line of Lex.

import "std.io" as io

import "std.str" as str

import "std.int" as int

import "std.env" as env

import "std.net" as net

import "std.time" as time

import "lex-schema/json_value" as jv

import "lex-web/router" as router

import "lex-web/ctx" as ctx

import "lex-web/response" as resp

import "lex-orm/connection" as conn

import "lex-trail/log" as tlog

import "lex-trail/replay" as replay

import "lex-trail/anchor" as anchor

import "lex-device-identity/src/device_identity" as di

import "./auth" as auth

import "./codec" as codec

fn port() -> [env] Int {
  match env.get("PORT") {
    None => 8090,
    Some(p) => match str.to_int(p) {
      Some(n) => n,
      None => 8090,
    },
  }
}

fn attest_key() -> [env] Str {
  match env.get("ATTEST_KEY") {
    None => "",
    Some(k) => k,
  }
}

fn db_target() -> [env] Str {
  match env.get("DB_URL") {
    Some(u) => u,
    None => match env.get("DB_PATH") {
      Some(p) => p,
      None => "./attest.db",
    },
  }
}

# ---- handlers -------------------------------------------------------
fn handle_append(c :: ctx.Ctx, log :: tlog.Log) -> [sql, time] resp.Response {
  match jv.parse(c.body) {
    Err(_) => resp.bad_request(codec.err("body is not JSON")),
    Ok(j) => {
      let kind := codec.field(j, "kind")
      if str.is_empty(kind) {
        resp.bad_request(codec.err("kind is required — an event with no kind cannot be found again"))
      } else {
        match tlog.append(log, kind, codec.parent_of(j), codec.payload_of(j)) {
          Err(e) => resp.json_status(500, codec.err(str.concat("append failed: ", e))),
          Ok(ev) => resp.json_status(201, jv.stringify(codec.event_json(ev))),
        }
      }
    },
  }
}

fn handle_chain(c :: ctx.Ctx, log :: tlog.Log) -> [sql] resp.Response {
  let id := match ctx.path_param(c, "id") {
    Some(v) => v,
    None => "",
  }
  if str.is_empty(id) {
    resp.bad_request(codec.err("event id is required"))
  } else {
    let events := replay.walk_chain(log, id)
    resp.json(codec.events_json(events))
  }
}

fn handle_range(c :: ctx.Ctx, log :: tlog.Log) -> [sql] resp.Response {
  let from_ms := int_param(c, "from_ms", 0)
  let to_ms := int_param(c, "to_ms", 9999999999999)
  match tlog.range(log, from_ms, to_ms) {
    Err(e) => resp.json_status(500, codec.err(str.concat("range failed: ", e))),
    Ok(events) => resp.json(codec.events_json(events)),
  }
}

fn int_param(c :: ctx.Ctx, name :: Str, fallback :: Int) -> Int {
  match ctx.query_param(c, name) {
    None => fallback,
    Some(s) => match str.to_int(s) {
      Some(n) => n,
      None => fallback,
    },
  }
}

# Verification is the endpoint that earns the sidecar its keep: it answers
# "was this reading signed by the device that claims it, under a certificate
# this platform issued" without the caller holding any of the crypto.
fn handle_verify(c :: ctx.Ctx, now_ms :: Int) -> [crypto] resp.Response {
  match jv.parse(c.body) {
    Err(_) => resp.bad_request(codec.err("body is not JSON")),
    Ok(j) => {
      let cert := codec.field(j, "cert")
      let body := codec.field(j, "body")
      let sig := codec.field(j, "signature")
      let pub := codec.field(j, "platform_public_key")
      if str.is_empty(cert) or str.is_empty(body) or str.is_empty(sig) or str.is_empty(pub) {
        resp.bad_request(codec.err("cert, body, signature and platform_public_key are all required"))
      } else {
        match di.verify_reading(cert, body, sig, pub, now_ms) {
          Err(why) => resp.json(jv.stringify(JObj([("verified", JBool(false)), ("reason", JStr(why))]))),
          Ok(_) => resp.json(jv.stringify(JObj([("verified", JBool(true))]))),
        }
      }
    },
  }
}

# Commit to the log as it stands. The caller is expected to STORE what comes
# back, somewhere this service cannot reach — that is the entire mechanism, and
# an anchor left sitting in the database it commits to is worth nothing.
fn handle_anchor(now_ms :: Int, log :: tlog.Log) -> [sql, crypto] resp.Response {
  match anchor.compute(log, now_ms) {
    Err(e) => resp.json_status(500, codec.err(str.concat("anchor failed: ", e))),
    Ok(a) => resp.json_status(201, anchor.to_json(a)),
  }
}

# Hand back an anchor taken earlier and find out whether this log still
# reproduces it. A `false` here means the log changed inside a window that was
# supposed to be closed — by anyone, including whoever runs this service.
fn handle_anchor_verify(c :: ctx.Ctx, log :: tlog.Log) -> [sql, crypto] resp.Response {
  match jv.parse(c.body) {
    Err(_) => resp.bad_request(codec.err("body is not JSON")),
    Ok(j) => {
      let digest := codec.field(j, "digest")
      if str.is_empty(digest) {
        resp.bad_request(codec.err("digest is required — send back the anchor you were given"))
      } else {
        let a := { up_to_ms: int_field(j, "up_to_ms", 0), count: int_field(j, "count", 0), digest: digest }
        match anchor.verify(log, a) {
          Match => resp.json("{\"reproduces\":true}"),
          Diverged(d) => resp.json(jv.stringify(JObj([("reproduces", JBool(false)), ("expected_count", JInt(d.expected_count)), ("actual_count", JInt(d.actual_count)), ("expected_digest", JStr(d.expected_digest)), ("actual_digest", JStr(d.actual_digest))]))),
        }
      }
    },
  }
}

fn int_field(j :: jv.Json, key :: Str, fallback :: Int) -> Int {
  match jv.get_field(j, key) {
    Some(JInt(n)) => n,
    _ => fallback,
  }
}

fn build_router(log :: tlog.Log, key :: Str) -> router.Router {
  let r := router.new()
  let r := router.route_effectful(r, "POST", "/v1/events", fn (c :: ctx.Ctx) -> [io, time, crypto, random, sql, fs_read, fs_write, net, concurrent, llm, proc, approval] resp.Response {
    if auth.authed(key, c) {
      handle_append(c, log)
    } else {
      resp.unauthorized(auth.refusal(key))
    }
  })
  let r := router.route_effectful(r, "GET", "/v1/events/:id/chain", fn (c :: ctx.Ctx) -> [io, time, crypto, random, sql, fs_read, fs_write, net, concurrent, llm, proc, approval] resp.Response {
    if auth.authed(key, c) {
      handle_chain(c, log)
    } else {
      resp.unauthorized(auth.refusal(key))
    }
  })
  let r := router.route_effectful(r, "GET", "/v1/events", fn (c :: ctx.Ctx) -> [io, time, crypto, random, sql, fs_read, fs_write, net, concurrent, llm, proc, approval] resp.Response {
    if auth.authed(key, c) {
      handle_range(c, log)
    } else {
      resp.unauthorized(auth.refusal(key))
    }
  })
  let r := router.route_effectful(r, "POST", "/v1/verify", fn (c :: ctx.Ctx) -> [io, time, crypto, random, sql, fs_read, fs_write, net, concurrent, llm, proc, approval] resp.Response {
    if auth.authed(key, c) {
      handle_verify(c, time.now_ms())
    } else {
      resp.unauthorized(auth.refusal(key))
    }
  })
  let r := router.route_effectful(r, "POST", "/v1/anchors", fn (c :: ctx.Ctx) -> [io, time, crypto, random, sql, fs_read, fs_write, net, concurrent, llm, proc, approval] resp.Response {
    if auth.authed(key, c) {
      handle_anchor(time.now_ms(), log)
    } else {
      resp.unauthorized(auth.refusal(key))
    }
  })
  let r := router.route_effectful(r, "POST", "/v1/anchors/verify", fn (c :: ctx.Ctx) -> [io, time, crypto, random, sql, fs_read, fs_write, net, concurrent, llm, proc, approval] resp.Response {
    if auth.authed(key, c) {
      handle_anchor_verify(c, log)
    } else {
      resp.unauthorized(auth.refusal(key))
    }
  })
  router.route(r, "GET", "/health", fn (_c :: ctx.Ctx) -> resp.Response {
    resp.json("{\"ok\":true}")
  })
}

fn main() -> [net, io, time, env, sql, fs_read, fs_write, concurrent, random, crypto, llm, proc, approval] Unit {
  let p := port()
  let key := attest_key()
  let target := db_target()
  let __b := io.print("=== lex-attest ===")
  let __b2 := io.print(str.concat("    port: ", int.to_str(p)))
  let __b3 := io.print(str.concat("    db:   ", target))
  let __b4 := if str.is_empty(key) {
    io.print("    ATTEST_KEY is not set — every route except /health will refuse")
  } else {
    io.print("    auth: bearer")
  }
  match tlog.open(target) {
    Err(e) => io.print(str.concat("! could not open the trail: ", e)),
    Ok(log) => {
      let r := build_router(log, key)
      let __r := io.print("    ready.")
      net.serve_fn(p, fn (req :: Request) -> [io, time, crypto, random, sql, fs_read, fs_write, net, concurrent, llm, proc, approval] Response {
        let raw := { body: req.body, method: req.method, path: req.path, query: req.query, headers: req.headers }
        let result := router.dispatch(r, raw)
        { status: result.status, body: BodyStr(result.body), headers: result.headers }
      })
    },
  }
}

