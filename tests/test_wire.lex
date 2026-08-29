# lex-attest — the gate, and the wire contract.
#
# Both modules under test are effect-free, so this suite runs on `io` alone —
# for its own failure reporting and nothing else. That is why src/auth.lex and
# src/codec.lex are separate from src/server.lex: reaching them through the
# handlers would drag sql, net and the rest into the test runner, and a suite
# that needs a database to check a field name is testing the wrong thing.

import "std.io" as io

import "std.str" as str

import "std.int" as int

import "std.list" as list

import "std.map" as map

import "lex-schema/json_value" as jv

import "lex-web/ctx" as ctx

import "../src/auth" as auth

import "../src/codec" as codec

fn assert_true(cond :: Bool, label :: Str) -> Result[Unit, Str] {
  if cond {
    Ok(())
  } else {
    Err(label)
  }
}

fn req(headers :: List[(Str, Str)]) -> ctx.Ctx {
  { method: "POST", path: "/v1/events", query: "", body: "", path_params: map.new(), headers: map.from_list(headers), state: map.new() }
}

fn bearer(t :: Str) -> ctx.Ctx {
  req([("authorization", str.concat("Bearer ", t))])
}

# ---- the gate is fail-closed ----------------------------------------
# An unset ATTEST_KEY must disable writes, not open them. A trial deployment
# that accepted anonymous appends would be building an evidence chain anyone
# can write to, which is worse than having none: it looks like provenance.
fn test_an_unset_key_refuses_everything() -> Result[Unit, Str] {
  assert_true(not auth.authed("", bearer("anything")) and not auth.authed("", bearer("")) and not auth.authed("", req([])), "with no ATTEST_KEY set, no request is authorised — including one carrying a plausible token")
}

fn test_the_configured_key_is_admitted() -> Result[Unit, Str] {
  assert_true(auth.authed("s3cret", bearer("s3cret")), "the configured key admits the request")
}

fn test_anything_but_the_key_is_refused() -> Result[Unit, Str] {
  assert_true(not auth.authed("s3cret", bearer("wrong")) and not auth.authed("s3cret", bearer("s3cretMORE")) and not auth.authed("s3cret", bearer("s3cre")) and not auth.authed("s3cret", req([("authorization", "Basic s3cret")])) and not auth.authed("s3cret", req([])), "only an exact bearer match is admitted — not a prefix, an extension, another scheme, or nothing")
}

# The two refusals are different operator problems, so they must read
# differently: one is a missing env var, the other is a bad caller.
fn test_the_refusal_says_which_problem_it_is() -> Result[Unit, Str] {
  assert_true(str.contains(auth.refusal(""), "ATTEST_KEY") and not str.contains(auth.refusal("k"), "ATTEST_KEY"), "an unset key and a bad token must not produce the same message")
}

# ---- the wire contract ----------------------------------------------
fn body(raw :: Str) -> jv.Json {
  match jv.parse(raw) {
    Ok(j) => j,
    Err(_) => JObj([]),
  }
}

# Omitting `parent` and sending "" both mean "this event starts a chain". An
# empty string must never reach the trail as a link to an event whose id is "".
fn test_absent_and_empty_parent_both_mean_root() -> Result[Unit, Str] {
  let absent := match codec.parent_of(body("{\"kind\":\"a\"}")) {
    None => true,
    Some(_) => false,
  }
  let empty := match codec.parent_of(body("{\"kind\":\"a\",\"parent\":\"\"}")) {
    None => true,
    Some(_) => false,
  }
  assert_true(absent and empty, "an absent parent and an empty parent both mean root, so neither can link to the empty id")
}

fn test_a_real_parent_is_carried() -> Result[Unit, Str] {
  match codec.parent_of(body("{\"kind\":\"a\",\"parent\":\"abc123\"}")) {
    None => Err("a supplied parent must be carried through"),
    Some(p) => assert_true(p == "abc123", "the parent id is carried verbatim"),
  }
}

# The event id is the hash of the payload TEXT, so two callers sending the same
# object must land on the same string or they will land on different ids.
fn test_the_same_object_canonicalises_the_same_way() -> Result[Unit, Str] {
  let a := codec.payload_of(body("{\"payload\":{\"kwh\":4,\"cp\":\"x\"}}"))
  let b := codec.payload_of(body("{\"payload\":{\"kwh\":4,\"cp\":\"x\"}}"))
  assert_true(a == b and not str.is_empty(a), str.concat("the same payload must canonicalise identically, got ", a))
}

fn test_a_missing_payload_is_an_empty_object() -> Result[Unit, Str] {
  assert_true(codec.payload_of(body("{\"kind\":\"a\"}")) == "{}", "an event with no payload carries an empty object, not an empty string")
}

# A caller sends `payload` as a JSON value, not a pre-encoded string. If that
# ever silently accepted a string, ids would change under callers who had done
# nothing wrong.
fn test_the_payload_is_a_value_not_a_string() -> Result[Unit, Str] {
  let obj := codec.payload_of(body("{\"payload\":{\"a\":1}}"))
  assert_true(str.contains(obj, "\"a\"") and str.contains(obj, "1"), str.concat("an object payload survives as an object, got ", obj))
}

fn test_the_error_envelope_is_parseable() -> Result[Unit, Str] {
  match jv.parse(codec.err("he said \"no\"")) {
    Err(_) => Err("err must produce parseable JSON even when the message has quotes"),
    Ok(j) => assert_true(codec.field(j, "error") == "he said \"no\"", "the message survives the round trip"),
  }
}

fn results() -> List[(Str, Result[Unit, Str])] {
  [("an_unset_key_refuses_everything", test_an_unset_key_refuses_everything()), ("the_configured_key_is_admitted", test_the_configured_key_is_admitted()), ("anything_but_the_key_is_refused", test_anything_but_the_key_is_refused()), ("the_refusal_says_which_problem_it_is", test_the_refusal_says_which_problem_it_is()), ("absent_and_empty_parent_both_mean_root", test_absent_and_empty_parent_both_mean_root()), ("a_real_parent_is_carried", test_a_real_parent_is_carried()), ("the_same_object_canonicalises_the_same_way", test_the_same_object_canonicalises_the_same_way()), ("a_missing_payload_is_an_empty_object", test_a_missing_payload_is_an_empty_object()), ("the_payload_is_a_value_not_a_string", test_the_payload_is_a_value_not_a_string()), ("the_error_envelope_is_parseable", test_the_error_envelope_is_parseable())]
}

fn report(rs :: List[(Str, Result[Unit, Str])]) -> [io] Int {
  list.fold(rs, 0, fn (n :: Int, r :: (Str, Result[Unit, Str])) -> [io] Int {
    match r {
      (_, Ok(_)) => n,
      (name, Err(why)) => {
        let __p := io.print(str.concat("FAIL ", str.concat(name, str.concat(" — ", why))))
        n + 1
      },
    }
  })
}

# The stdlib is total — there is no `panic` — so a division by zero is the
# raise. `zero` arrives as an argument so it survives constant folding.
fn raise_failure(zero :: Int) -> Int {
  1 / zero
}

fn run_all() -> [io] Unit {
  let failures := report(results())
  if failures == 0 {
    ()
  } else {
    let __p := io.print(str.concat(int.to_str(failures), " test(s) failed"))
    let __boom := raise_failure(0)
    ()
  }
}

