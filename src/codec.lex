# codec.lex — the wire shapes, and nothing else.
#
# Separate from the handlers so the JSON contract can be tested without a
# database or an HTTP server behind it. lex checks effects per program rather
# than per function, so a decoder living beside a handler inherits the
# handler's whole footprint — sql, net and the rest — and the tests then need
# permission to reach a database in order to check a field name.

import "std.str" as str

import "std.int" as int

import "std.list" as list

import "lex-schema/json_value" as jv

import "lex-trail/src/event" as ev

fn field(j :: jv.Json, key :: Str) -> Str {
  match jv.get_field(j, key) {
    Some(JStr(s)) => s,
    _ => "",
  }
}

# `parent` absent and `parent` empty both mean "this event begins a chain".
# A caller that omits the field and one that sends "" are saying the same
# thing, and an empty-string parent must never reach the trail as a link to
# an event whose id is the empty string.
fn parent_of(j :: jv.Json) -> Option[Str] {
  let p := field(j, "parent")
  if str.is_empty(p) {
    None
  } else {
    Some(p)
  }
}

# The payload travels as a JSON *value*, not a string, so callers do not have
# to double-encode. It is re-stringified canonically here because the event id
# is the hash of the payload text: two callers sending the same object with
# different key spacing must land on the same id.
fn payload_of(j :: jv.Json) -> Str {
  match jv.get_field(j, "payload") {
    Some(v) => jv.stringify(v),
    None => "{}",
  }
}

fn err(msg :: Str) -> Str {
  jv.stringify(JObj([("error", JStr(msg))]))
}

fn event_json(e :: ev.Event) -> jv.Json {
  let parent := match e.parent {
    Some(p) => JStr(p),
    None => JNull,
  }
  JObj([("id", JStr(e.id)), ("kind", JStr(e.kind)), ("parent", parent), ("payload", JStr(e.payload_json)), ("ts_ms", JInt(e.ts_ms))])
}

fn events_json(es :: List[ev.Event]) -> Str {
  jv.stringify(JList(list.map(es, event_json)))
}

