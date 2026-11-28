#!/usr/bin/env python3
"""SP2-78 independently expected fixtures (EXPERIMENTAL forms, not a released format).

This script is the second implementation: it is written from the field order
documented in process/drwa/certificateContract.go, transferAuthorization.go and
supplyEvidence.go and shares no code with the Go product. It uses only the
Python standard library and PyNaCl (Ed25519):

  frame(f1..fn) = for each field: byte 0x0a, unsigned LEB128 length, the bytes
                  (the wire form of a protobuf message with one repeated bytes
                  field number 1, which is what the native Batch type encodes)
  H(x)          = BLAKE2b with a 32-byte digest and no key
  u32/u64       = big-endian fixed width
  signature     = Ed25519 over the 32-byte digest itself

Run: python3 sp2_78_experimental_fixtures.py > sp2_78_experimental_fixtures.json
All keys are derived from public labels below. They are test keys.
"""
import hashlib
import json
import sys

from nacl.signing import SigningKey


def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def frame(*fields):
    out = bytearray()
    for f in fields:
        out += b"\x0a" + varint(len(f)) + f
    return bytes(out)


def H(x):
    return hashlib.blake2b(x, digest_size=32).digest()


def u32(n):
    return n.to_bytes(4, "big")


def u64(n):
    return n.to_bytes(8, "big")


def big(n):
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def hx(b):
    return b.hex()


keys = [SigningKey(hashlib.sha256(b"SP2-78 experimental fixture member %d" % i).digest()) for i in range(5)]
members = [bytes(k.verify_key) for k in keys]
set_id = b"sp2-78-fixture-authority-set"
set_hash = H(frame(*members))
set_version = 1
threshold = 3
signers = [0, 2, 4]


def sign(digest):
    return [hx(keys[i].sign(digest).signature) for i in signers]


def body(network, operation, version, purpose, scope, subjects, kind, payload, not_before, until, nonce):
    return frame(b"DRWA/CERTIFICATE_BODY/experimental1", network, operation, u64(version), purpose, scope,
                 frame(*subjects), kind, payload, set_id, u64(set_version), set_hash, u64(0), b"",
                 u64(not_before), u64(until), nonce)


network = H(b"DRWA/NETWORK/v1" + b"fixture-chain" + bytes(32))
scope = b"sp2-78-fixture-programme"
out = {"experimental": True, "note": "SP2-78 experimental forms; no production format",
       "hash": "BLAKE2b-256", "signature": "Ed25519 over the digest",
       "authority_set": {"id": hx(set_id), "hash": hx(set_hash), "version": set_version, "threshold": threshold,
                         "members": [hx(m) for m in members], "signers": signers}}

# 1. Scoped authority certificate (C8): Emergency Authority, emergency add, direct phase.
use, phase, source = 17, 1, 0
subject, action, owner = b"program-subject", b"exact immutable action", b"exact action owner"
commitment = b"complete class body commitment"
role, cert_kind = b"Emergency Authority", b"add"
kind = frame(u32(use), u32(phase), cert_kind, u32(source), b"", u32(0xFFFFFFFF), u32(1), action, owner)
raw = body(network, b"DRWA/SCOPED_AUTHORITY/experimental1", 1, role, scope, [subject], kind, commitment, 100, 120, b"")
out["scoped_authority"] = {
    "use": use, "phase": phase, "source": source, "role": role.decode(), "kind": cert_kind.decode(),
    "locus": 0xFFFFFFFF, "target_shard": 1, "network": hx(network), "scope": hx(scope), "subject": hx(subject),
    "action": hx(action), "owner": hx(owner), "body_commitment": hx(commitment), "not_before": 100, "until": 120,
    "expected_body": hx(raw), "expected_digest": hx(H(raw)), "signatures": sign(H(raw))}

# 2. Transfer-authorization certificate (C13).
token, token_nonce = b"FIXT-0a1b2c", 7
src, dst = bytes([0x11]) * 32, bytes([0x22]) * 32
quantity, ceb_epoch, auth_nonce = 1500, 3, 9
travel, evidence = b"TRAVEL_RULE_SATISFIED", H(b"fixture evidence")
effect = frame(b"DRWA/AUTH_TRANSFER/EFFECT/experimental1", token, u64(token_nonce), src, dst, big(quantity), u64(ceb_epoch))
payload = frame(b"DRWA/AUTH_TRANSFER/PAYLOAD/experimental1", H(effect), big(quantity), u64(ceb_epoch), u64(auth_nonce), travel, evidence)
raw = body(network, b"DRWA/AUTHORIZED_TRANSFER/experimental1", 1, b"AUTHORIZED_TRANSFER", scope,
           [token, u64(token_nonce), src, dst], b"DRWAAuthorizedTransfer", H(payload), 1000, 1060, u64(auth_nonce))
out["transfer_authorization"] = {
    "network": hx(network), "scope": hx(scope), "token": hx(token), "token_nonce": token_nonce, "source": hx(src),
    "destination": hx(dst), "quantity": quantity, "ceb_epoch": ceb_epoch, "authorization_nonce": auth_nonce,
    "travel_rule": hx(travel), "evidence": hx(evidence), "not_before": 1000, "until": 1060,
    "expected_effect_digest": hx(H(effect)), "expected_payload_digest": hx(H(payload)),
    "expected_body": hx(raw), "expected_digest": hx(H(raw)), "signatures": sign(H(raw))}

# 3. Closure-bound supply evidence (S1).
origin_shard, closure, cumulative, live = 1, 4, 1000000, 999000
ceb_hash, gas_action = H(b"fixture current CEB"), b"fixture requalification action"
supply_record = frame(u32(1), token, u32(0), bytes([0x33]) * 32, u32(origin_shard), big(cumulative), big(live), b"", u64(12))
binding = frame(b"DRWA/SUPPLY_EVIDENCE/experimental1", token, u64(ceb_epoch), ceb_hash, gas_action, u64(closure), u32(origin_shard))
identity = H(binding)
out["supply_evidence"] = {
    "token": hx(token), "ceb_epoch": ceb_epoch, "ceb_hash": hx(ceb_hash), "action": hx(gas_action), "closure": closure,
    "origin_shard": origin_shard, "family": 0, "origin": hx(bytes([0x33]) * 32), "cumulative_issued": cumulative,
    "live_supply": live, "next_supply_nonce": 12,
    "expected_supply_record": hx(supply_record), "expected_binding": hx(binding),
    "expected_key": hx(b"ELRONDDRWA@supplyEvidence@" + identity),
    "expected_value": hx(frame(identity, big(cumulative), H(supply_record)))}

json.dump(out, sys.stdout, indent=1, sort_keys=True)
sys.stdout.write("\n")
