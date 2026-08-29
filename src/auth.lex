# auth.lex — the sidecar's bearer gate.
#
# Fail-closed on purpose: with ATTEST_KEY unset the service answers /health and
# refuses everything else. A trial deployment that silently accepted anonymous
# writes would be building an evidence chain anyone could write to, which is
# worse than no chain — it looks like provenance and is not.

import "std.str" as str

import "lex-web/ctx" as ctx

fn authed(key :: Str, c :: ctx.Ctx) -> Bool {
  if str.is_empty(key) {
    false
  } else {
    match ctx.bearer_token(c) {
      None => false,
      Some(tok) => tok == key,
    }
  }
}

# Why a request was refused, so an operator can tell "I forgot the env var"
# from "the caller sent the wrong token" without reading the source.
#
# Plain prose, not JSON: lex-web's `unauthorized` wraps this in its own error
# envelope, and handing it JSON produced a double-encoded body that no client
# could parse.
fn refusal(key :: Str) -> Str {
  if str.is_empty(key) {
    "attestation is disabled: ATTEST_KEY is not set"
  } else {
    "missing or invalid bearer token"
  }
}

