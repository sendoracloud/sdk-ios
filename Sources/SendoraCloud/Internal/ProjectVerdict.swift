import Foundation

// ADR-033 B8 / INV-15 — `projectVerdict()`, the ProjectGuard every InstallTx is
// judged by BEFORE any assignment (§3.3 `commit()` header). A VERBATIM port of
// `packages/shared/src/auth-machine/project-verdict.ts`; the shared fixture
// `auth-transitions.conformance.json` carries LITERAL JWTs so this port needs
// only a DECODER (never an encoder, never a signature check).
//
// WHY A PURE FUNCTION. `withheld` (§3.2) is "a pure function of (disk record,
// config), recomputed every hydrate, never persisted" — so a re-init with the
// right key or a rollback needs no migration. That holds only if the verdict
// reads nothing but its two arguments: no `Date` (expiry is irrelevant — a stale
// token still names its project truthfully), no network, no storage, and no
// Foundation base64 leniency that differs from the other three ports.
//
// The three answers, and why absent ≠ match (§3.3, §8-Q13):
//
//   expected unset                                   → .match    (guard off)
//   token missing / undecodable / claim KEY absent   → .unknown  (NOT match: a
//       pre-s58.276 token says nothing about its project; the SDK stays
//       `unknown` and lets the refresh answer)
//   claim === null                                   → .mismatch (the server
//       emits an EXPLICIT null for the org-wide pool; under a project-bound
//       expectedProjectId an org-wide session is the wrong tenant)
//   claim is a string                                → equal ? .match : .mismatch
//
// ⚠ The guard is ADVISORY (a client consistency check against a wrong-key
// build), not an authorization boundary, and it never produces a dead-token
// verdict (INV-6/INV-15).

internal enum ProjectVerdict: String {
    case match
    case mismatch
    case unknown
}

/// The JWT claim this guard reads. Emitted ALWAYS by the backend since s58.276.
internal let projectClaimName = "project"

internal func projectVerdict(expectedProjectId: String?, accessJwt: String?) -> ProjectVerdict {
    // Guard off. Checked FIRST so an SDK without the opt-in never pays for a
    // decode and never reports `unknown` on a legacy token.
    guard let expected = expectedProjectId else { return .match }

    guard let payload = decodeJwtPayload(accessJwt) else { return .unknown }

    // Key presence, not truthiness: `{ "project": null }` is PRESENT and means
    // "org-wide pool"; `{}` is ABSENT and means "minted before the claim
    // existed". Collapsing those two is the exact mistake the fixture
    // `claim_absent` exists to catch (§5 wave 1 "treat an absent claim as match
    // → red"). `JSONSerialization` surfaces an explicit null as `NSNull`, so the
    // dictionary lookup distinguishes the two.
    guard let raw = payload[projectClaimName] else { return .unknown }
    if raw is NSNull { return .mismatch }
    if let claim = raw as? String { return claim == expected ? .match : .mismatch }

    // Present, decodable, and not a string — the server never emits this shape.
    // It is a value that disagrees with the expected string, so it is a
    // mismatch, not an unknown: `unknown` would park the SDK waiting for a
    // refresh to "settle" a claim that is already settled and wrong.
    return .mismatch
}

/// Decode a compact JWS payload (`header.payload.signature`) WITHOUT verifying
/// the signature. The verdict only needs to READ a claim from a token the SDK
/// already holds (the server verifies on every request).
///
/// Returns `nil` for anything that is not a three-segment token whose second
/// segment base64url-decodes to a UTF-8 JSON object. Arrays, scalars and
/// malformed input are all "undecodable".
internal func decodeJwtPayload(_ token: String?) -> [String: Any]? {
    guard let token = token, !token.isEmpty else { return nil }
    let parts = token.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 3 else { return nil }
    guard let bytes = decodeBase64Url(String(parts[1])) else { return nil }
    guard let json = decodeUtf8Strict(bytes) else { return nil }
    guard let data = json.data(using: .utf8),
          let parsed = try? JSONSerialization.jsonObject(with: data),
          let object = parsed as? [String: Any] else { return nil }
    return object
}

/// A string claim off an access token, or `nil` when the token is undecodable
/// or the claim is absent / not a string. Used for `sid` (the identity CAS key,
/// INV-2) and `sub`; `project` goes through `projectVerdict` instead because
/// absent and null mean different things there.
internal func jwtStringClaim(_ token: String?, _ name: String) -> String? {
    return decodeJwtPayload(token)?[name] as? String
}

/// The tri-state `project` claim as recorded on a HELD slot (§3.2 `held_guests`):
/// a string when readable, `nil` when the claim is null, absent or the token is
/// unreadable. A slot's `nil` is NOT a client-side mismatch — RESTORE judges the
/// refresh response instead (fixture `restore_null_slot_project_judged_on_response`).
internal func jwtProjectClaimForSlot(_ token: String?) -> String? {
    return decodeJwtPayload(token)?[projectClaimName] as? String
}

// ─── base64url (RFC 4648 §5) → bytes, no Foundation leniency ───────────────
//
// Accepts the url-safe alphabet (`-` `_`) AND the standard one (`+` `/`) so a
// token that was re-encoded by a careless proxy still decodes; tolerates the
// optional `=` padding JWS omits. Any other character, or a length ≡ 1 (mod 4)
// after padding removal (impossible for real base64), is "undecodable" — the
// same contract as the TypeScript decoder, so the four ports agree on every
// fixture token.

private let base64UrlLookup: [Int8] = {
    var table = [Int8](repeating: -1, count: 128)
    let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".utf8)
    for (i, c) in alphabet.enumerated() { table[Int(c)] = Int8(i) }
    table[Int(UInt8(ascii: "-"))] = 62
    table[Int(UInt8(ascii: "_"))] = 63
    table[Int(UInt8(ascii: "+"))] = 62
    table[Int(UInt8(ascii: "/"))] = 63
    return table
}()

internal func decodeBase64Url(_ input: String) -> [UInt8]? {
    let chars = Array(input.utf8)
    var end = chars.count
    while end > 0 && chars[end - 1] == UInt8(ascii: "=") { end -= 1 }
    if end % 4 == 1 { return nil }
    var out = [UInt8]()
    out.reserveCapacity((end * 3) / 4)
    var buffer: UInt32 = 0
    var bits = 0
    for i in 0..<end {
        let code = chars[i]
        guard code < 128 else { return nil }
        let v = base64UrlLookup[Int(code)]
        guard v >= 0 else { return nil }
        buffer = (buffer << 6) | UInt32(v)
        bits += 6
        if bits >= 8 {
            bits -= 8
            out.append(UInt8((buffer >> UInt32(bits)) & 0xff))
        }
    }
    return out
}

// ─── UTF-8 → String, strict ────────────────────────────────────────────────
//
// A JWT payload is JSON and JSON is UTF-8; the `name` claim can carry any
// script. A decoder that only handled ASCII would report a perfectly good token
// as "undecodable" for a player whose display name is in Devanagari — and
// `unknown` on every hydrate is a session that never settles. Strict: overlong
// forms, lone surrogates and truncated sequences return `nil` (the TS port's
// contract; Foundation's `String(bytes:encoding:)` is also strict but its
// handling of the BOM differs, so the hand-rolled decoder keeps the ports equal).

internal func decodeUtf8Strict(_ bytes: [UInt8]) -> String? {
    var scalars = String.UnicodeScalarView()
    var i = 0
    let n = bytes.count
    while i < n {
        let b0 = bytes[i]
        var cp: UInt32
        var need: Int
        if b0 < 0x80 {
            cp = UInt32(b0); need = 0
        } else if b0 >= 0xc2 && b0 <= 0xdf {
            cp = UInt32(b0 & 0x1f); need = 1
        } else if b0 >= 0xe0 && b0 <= 0xef {
            cp = UInt32(b0 & 0x0f); need = 2
        } else if b0 >= 0xf0 && b0 <= 0xf4 {
            cp = UInt32(b0 & 0x07); need = 3
        } else {
            return nil // 0x80–0xC1 continuation/overlong lead, 0xF5+ out of range
        }
        if i + need >= n { return nil } // truncated multi-byte sequence
        if need > 0 {
            for k in 1...need {
                let b = bytes[i + k]
                if (b & 0xc0) != 0x80 { return nil } // not a continuation byte
                cp = (cp << 6) | UInt32(b & 0x3f)
            }
        }
        if (need == 2 && cp < 0x800) || (need == 3 && (cp < 0x10000 || cp > 0x10ffff)) || (cp >= 0xd800 && cp <= 0xdfff) {
            return nil
        }
        guard let scalar = Unicode.Scalar(cp) else { return nil }
        scalars.append(scalar)
        i += need + 1
    }
    return String(scalars)
}
