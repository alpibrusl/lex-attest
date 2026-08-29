# destination.lex — where an anchor gets published, and what it looks like there.
#
# An anchor is only worth taking if it ends up somewhere its subject cannot
# reach. This module names the somewheres. It is pure: it decides the URL, the
# body and the content type, and nothing here performs a request — which is
# what lets the wire format be tested without a network or a counterparty.
#
# Two destinations work today, and both are plain HTTP:
#
#   Webhook          POST the anchor to a URL the counterparty controls. Free,
#                    needs no third party, and settles the case that actually
#                    matters: two parties who will later disagree, each holding
#                    the same commitment from before they disagreed.
#
#   OpenTimestamps   POST the raw digest to a public calendar, which commits it
#                    into Bitcoin. No wallet, no gas, no transaction building —
#                    the calendar aggregates many digests into one on-chain
#                    commitment, and hands back a proof. This is blockchain
#                    anchoring, reached over HTTP.
#
# Two more are worth having and are NOT here, because neither is a small piece
# of work and pretending otherwise would be worse than the gap:
#
#   direct EVM       an EIP-1559 transaction carrying the digest. The crypto is
#                    all present (keccak256, secp256k1_sign_digest, hex) but
#                    there is no RLP encoder anywhere in the ecosystem, so the
#                    transaction encoder has to be written and tested against a
#                    testnet before anyone should trust it with a key.
#
#   RFC 3161 TSA     an eIDAS qualified timestamp — legally recognised in the
#                    EU and the strongest option for a European product. The
#                    request is a small DER structure; the RESPONSE is CMS
#                    SignedData, and parsing that correctly is the real work.
#                    There is no ASN.1 support to build on.

import "std.str" as str

import "std.int" as int

# A place an anchor can be published.
type Destination = Webhook({ url :: Str }) | OpenTimestamps({ calendar :: Str })

# What happened. Carries the destination so a caller publishing to several can
# tell which one refused.
type Outcome = Published({ destination :: Str, detail :: Str }) | Failed({ destination :: Str, why :: Str })

fn describe(d :: Destination) -> Str {
  match d {
    Webhook(w) => str.concat("webhook ", w.url),
    OpenTimestamps(o) => str.concat("opentimestamps ", o.calendar),
  }
}

fn endpoint(d :: Destination) -> Str {
  match d {
    Webhook(w) => w.url,
    OpenTimestamps(o) => str.concat(strip_slash(o.calendar), "/digest"),
  }
}

# A calendar given as "https://a.pool.opentimestamps.org/" and one given
# without the slash must produce the same endpoint, or half the callers get a
# double slash and a 404 they cannot explain.
fn strip_slash(u :: Str) -> Str {
  if str.ends_with(u, "/") {
    str.slice(u, 0, str.len(u) - 1)
  } else {
    u
  }
}

fn content_type(d :: Destination) -> Str {
  match d {
    Webhook(_) => "application/json",
    OpenTimestamps(_) => "application/octet-stream",
  }
}

# The webhook receives the anchor as JSON — it is a counterparty's system, and
# it wants something it can store and read back.
#
# A calendar receives the digest and nothing else: it is a public service that
# should learn as little as possible, and the count and window are none of its
# business.
# Takes the anchor already rendered rather than the Anchor type: importing
# lex-trail/anchor here would pull sql, crypto and time into every consumer of
# this module, and the tests would then need a database to check a URL.
fn body_for(d :: Destination, anchor_json :: Str, digest :: Str) -> Str {
  match d {
    Webhook(_) => anchor_json,
    OpenTimestamps(_) => digest,
  }
}

# Whether the destination is usable as configured. An empty URL is the
# configuration mistake that would otherwise surface as a confusing transport
# error at the moment someone needed the anchor.
fn problem(d :: Destination) -> Option[Str] {
  let u := match d {
    Webhook(w) => w.url,
    OpenTimestamps(o) => o.calendar,
  }
  if str.is_empty(u) {
    Some("destination has no URL")
  } else {
    if str.starts_with(u, "http://") or str.starts_with(u, "https://") {
      None
    } else {
      Some(str.concat("destination URL must be http(s): ", u))
    }
  }
}

fn parse(kind :: Str, url :: Str) -> Result[Destination, Str] {
  if kind == "webhook" {
    Ok(Webhook({ url: url }))
  } else {
    if kind == "opentimestamps" {
      Ok(OpenTimestamps({ calendar: url }))
    } else {
      Err(str.concat("unknown destination kind: ", kind))
    }
  }
}

fn outcome_json(o :: Outcome) -> Str {
  match o {
    Published(p) => str.join(["{\"published\":true,\"destination\":\"", p.destination, "\",\"detail\":\"", p.detail, "\"}"], ""),
    Failed(f) => str.join(["{\"published\":false,\"destination\":\"", f.destination, "\",\"error\":\"", f.why, "\"}"], ""),
  }
}
