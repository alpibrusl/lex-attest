# publish.lex — the one part of publishing that touches the network.
#
# Deliberately thin. Everything about WHERE an anchor goes and WHAT is sent
# lives in destination.lex, which is pure and tested; this performs the POST
# and classifies the answer. Keeping the split means the wire format is checked
# on every CI run without a network, a counterparty, or a public calendar being
# reachable.

import "std.str" as str

import "std.int" as int

import "std.http" as http

import "std.bytes" as bytes

import "std.crypto" as crypto

import "./destination" as dest

fn http_err(e :: HttpError) -> Str {
  match e {
    TimeoutError => "timeout",
    TlsError(m) => str.concat("tls: ", m),
    NetworkError(m) => str.concat("network: ", m),
    DecodeError(m) => str.concat("decode: ", m),
  }
}

# A calendar wants the digest as 32 raw bytes, not as the 64 hex characters we
# carry it in. A webhook wants the JSON text as-is.
fn wire_bytes(d :: dest.Destination, payload :: Str) -> Bytes {
  match d {
    Webhook(_) => bytes.from_str(payload),
    OpenTimestamps(_) => match crypto.hex_decode(payload) {
      Ok(b) => b,
      Err(_) => bytes.from_str(payload),
    },
  }
}

fn publish(d :: dest.Destination, anchor_json :: Str, digest :: Str) -> [net] dest.Outcome {
  let name := dest.describe(d)
  match dest.problem(d) {
    Some(why) => Failed({ destination: name, why: why }),
    None => {
      let payload := dest.body_for(d, anchor_json, digest)
      match http.post(dest.endpoint(d), wire_bytes(d, payload), dest.content_type(d)) {
        Err(e) => Failed({ destination: name, why: http_err(e) }),
        Ok(res) => if res.status >= 400 {
          Failed({ destination: name, why: str.concat("HTTP ", int.to_str(res.status)) })
        } else {
          Published({ destination: name, detail: str.concat("HTTP ", int.to_str(res.status)) })
        },
      }
    },
  }
}

