import XCTest
@testable import SendoraCloud

// ADR-033 INV-11 ("one table, four ports") — this suite REPLAYS the shared
// fixture `packages/shared/src/auth-machine/auth-transitions.conformance.json`
// against the Swift port:
//
//   - every `transitions[]` row has a behavioural scenario (recording Keychain
//     double + scripted transport) that drives the machine from the row's `from`
//     state with the row's event and asserts the resulting state, the emitted
//     events (names + order) and the writes / no-writes the row prescribes;
//   - every `projectVerdictCases[]` entry drives the ported `projectVerdict`,
//     and — when its `context` is a transition — the install path too;
//   - the constants (slot keys, dead codes, release reasons, withheld reject
//     list, states) EQUAL the fixture's.
//
// The fixture is read from `packages/shared` by path (never copied — a copy
// drifts). A row the port cannot replay is a FAILURE here, never a skip.

// MARK: - Fixture decoding

struct ConformanceFixture: Decodable {
    let states: [String]
    let events: [String]
    let heldGuestSlots: Int
    let heldSlotKeys: [String]
    let deadCodes: [String]
    let releaseHeldOnEndReasons: [String]
    let rejectedInWithheld: [String]
    let acceptedInWithheld: [String]
    let projectClaim: String
    let transitions: [Transition]
    let unspecifiedByAdr: [Unspecified]
    let projectVerdictCases: [VerdictCase]

    struct Transition: Decodable {
        let id: String
        let from: StringOrList
        let event: StringOrList
        let guardText: String?
        let effects: [String]
        let emits: [String]
        let mutation: String
        let adr: String

        enum CodingKeys: String, CodingKey { case id, from, event, guardText = "guard", effects, emits, mutation, adr }
    }

    struct Unspecified: Decodable { let from: String; let event: String; let why: String }

    struct VerdictCase: Decodable {
        let id: String
        let context: String
        let expectedProjectId: String?
        let accessToken: String?
        /// `.none` = not a restore case; `.some(nil)` = slot project null; `.some(x)` = string.
        let slotProject: String??
        let verdict: String
        let row: String?
        let errorCode: String?
        let note: String

        enum CodingKeys: String, CodingKey { case id, context, expectedProjectId, accessToken, slotProject, verdict, row, errorCode, note }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            id = try c.decode(String.self, forKey: .id)
            context = try c.decode(String.self, forKey: .context)
            expectedProjectId = try c.decodeIfPresent(String.self, forKey: .expectedProjectId)
            accessToken = try c.decodeIfPresent(String.self, forKey: .accessToken)
            if c.contains(.slotProject) {
                slotProject = .some(try c.decodeNil(forKey: .slotProject) ? nil : try c.decode(String.self, forKey: .slotProject))
            } else {
                slotProject = nil
            }
            verdict = try c.decode(String.self, forKey: .verdict)
            row = try c.decodeIfPresent(String.self, forKey: .row)
            errorCode = try c.decodeIfPresent(String.self, forKey: .errorCode)
            note = try c.decode(String.self, forKey: .note)
        }
    }
}

enum StringOrList: Decodable {
    case one(String)
    case many([String])

    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if let s = try? c.decode(String.self) { self = .one(s); return }
        self = .many(try c.decode([String].self))
    }

    var values: [String] {
        switch self {
        case .one(let s): return [s]
        case .many(let list): return list
        }
    }
}

final class AuthMachineConformanceTests: XCTestCase {
    static let fixture: ConformanceFixture = {
        // Tests/SendoraCloudTests/<this file> → Tests → sdk-ios → packages
        let packages = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let url = packages.appendingPathComponent("shared/src/auth-machine/auth-transitions.conformance.json")
        let data = try! Data(contentsOf: url)
        return try! JSONDecoder().decode(ConformanceFixture.self, from: data)
    }()

    var fixture: ConformanceFixture { Self.fixture }

    // MARK: Negative controls — the fixture is what the shared package says it is

    func test_fixtureLoadsFromPackagesShared() {
        XCTAssertEqual(fixture.transitions.count, 36, "the ADR has 33 §3.3 rows + 3 §3.5-sourced rows")
        XCTAssertEqual(fixture.projectVerdictCases.count, 19)
        XCTAssertEqual(fixture.unspecifiedByAdr.count, 9)
        XCTAssertEqual(fixture.projectClaim, projectClaimName)
    }

    // MARK: Constants EQUAL the fixture's

    func test_statesMirrorTheFixtureInOrder() {
        let ported = fixture.states.map { SendoraCloudAuthStatus(rawValue: $0)?.rawValue }
        XCTAssertEqual(ported, fixture.states.map { Optional($0) }, "every fixture state has a Swift case with the same raw value")
        XCTAssertEqual(fixture.states.count, 5)
    }

    func test_heldSlotKeysAreTheFixtureLiteralsUnderTheIOSPrefix() {
        XCTAssertEqual(SendoraCloudAuth.heldGuestSlots, fixture.heldGuestSlots)
        XCTAssertEqual(SendoraStorage.heldSlotKeys, fixture.heldSlotKeys.map { "sendora_" + $0 })
        // The secure key set includes exactly the slots + auth_session (plus the frozen keys).
        for key in fixture.heldSlotKeys { XCTAssertTrue(SendoraStorage.secureKeys.contains("sendora_" + key), key) }
        XCTAssertTrue(SendoraStorage.secureKeys.contains("sendora_auth_session"))
        let slotKeysInSecureSet = SendoraStorage.secureKeys.filter { $0.hasPrefix("sendora_auth_held_") }
        XCTAssertEqual(slotKeysInSecureSet, fixture.heldSlotKeys.map { "sendora_" + $0 }, "no extra / dynamic slot keys")
    }

    func test_deadCodesAndReleaseReasonsAndWithheldListsEqualTheFixture() {
        XCTAssertEqual(SendoraCloudAuth.deadCodes, fixture.deadCodes)
        XCTAssertEqual(SendoraCloudAuth.releaseHeldOnEndReasons.map { $0.rawValue }, fixture.releaseHeldOnEndReasons)
        XCTAssertEqual(SendoraCloudAuth.rejectedInWithheld, fixture.rejectedInWithheld)
        XCTAssertEqual(fixture.acceptedInWithheld, ["HYDRATE", "DISCARD_WITHHELD", "SIGN_OUT"])
        for reason in fixture.releaseHeldOnEndReasons {
            XCTAssertNotNil(SendoraCloudRefreshEndReason(rawValue: reason), reason)
        }
    }

    // MARK: projectVerdict — every fixture case

    func test_projectVerdictEveryCase() {
        for c in fixture.projectVerdictCases {
            let got = projectVerdict(expectedProjectId: c.expectedProjectId, accessJwt: c.accessToken)
            XCTAssertEqual(got.rawValue, c.verdict, "\(c.id): \(c.note)")
        }
    }

    func test_projectVerdictTransitionCasesDriveTheInstallPath() {
        for c in fixture.projectVerdictCases where c.context != "verdict" {
            XCTContext.runActivity(named: c.id) { _ in
                switch c.context {
                case "hydrate": replayHydrateVerdictCase(c)
                case "mint": replayMintVerdictCase(c)
                case "restore": replayRestoreVerdictCase(c)
                default: XCTFail("\(c.id): unknown context \(c.context)")
                }
            }
        }
    }

    private func replayHydrateVerdictCase(_ c: ConformanceFixture.VerdictCase) {
        let h = AuthHarness(expectedProjectId: c.expectedProjectId)
        h.seedSession(user: AuthHarness.anonymousUser(), access: c.accessToken ?? "", refresh: "rt-hydrate")
        let secureBefore = h.secure.snapshot()
        let plainBefore = h.plain.snapshot()
        h.boot()
        switch c.verdict {
        case "mismatch":
            XCTAssertEqual(h.auth.status(), .withheld, c.id)
            XCTAssertEqual(c.row, "hydrate.project_mismatch")
            XCTAssertEqual(h.secure.snapshot(), secureBefore, "\(c.id): a withheld hydrate performs ZERO secure writes")
            XCTAssertEqual(h.plain.snapshot(), plainBefore, "\(c.id): no schema_version bump either")
            XCTAssertEqual(h.secure.writeCount, 0)
            let result = h.signIn()
            if case .failure(let error) = result {
                XCTAssertEqual(error.code, c.errorCode, c.id)
                XCTAssertEqual(error.kind, .config, c.id)
            } else { XCTFail("\(c.id): a verb must reject in withheld") }
        case "unknown":
            XCTAssertEqual(h.auth.status(), .unknown, c.id)
            XCTAssertEqual(c.row, "hydrate.gap_fill")
            XCTAssertEqual(h.secure.writeCount, 0, "\(c.id): nothing is installed from an unreadable claim")
        default:
            XCTAssertEqual(h.auth.status(), .anonymous, c.id)
        }
    }

    private func replayMintVerdictCase(_ c: ConformanceFixture.VerdictCase) {
        let h = AuthHarness(expectedProjectId: c.expectedProjectId)
        h.boot()
        h.transport.stub("POST", "/auth-service/anonymous",
                         Stub.session(user: Stub.user(id: "g-1", isAnonymous: true, project: TestJWT.projectB),
                                      tokens: Stub.tokens(access: c.accessToken ?? "", refresh: "rt-minted"), status: 201))
        let mark = h.secure.writeCount
        let result = h.mint()
        XCTAssertEqual(c.row, "mint.fresh")
        guard case .failure(let error) = result else { return XCTFail("\(c.id): a fresh-mint mismatch must reject") }
        XCTAssertEqual(error.code, c.errorCode, c.id)
        XCTAssertEqual(error.kind, .config)
        XCTAssertEqual(h.auth.status(), .signedOut, "\(c.id): nothing installed")
        XCTAssertEqual(h.secure.writesSince(mark).filter { $0.key.hasPrefix("sendora_auth_") }, [], "\(c.id): no auth key written")
        XCTAssertEqual(h.transport.lastRequest(to: "/auth-service/token/revoke")?.body?["refreshToken"] as? String, "rt-minted", "\(c.id): the minted refresh is revoked")
        XCTAssertNil(h.plain.string(forKey: "sendora_auth_mint_key"), "\(c.id): no relaunch lockout loop via a replayed mint key")
    }

    private func replayRestoreVerdictCase(_ c: ConformanceFixture.VerdictCase) {
        let h = AuthHarness(expectedProjectId: c.expectedProjectId)
        guard let slotProject = c.slotProject else { return XCTFail("\(c.id): restore case without slotProject") }
        h.seedSlot(0, AuthHarness.slot(userId: "g-held", refresh: "rt-held", heldAt: 1_000, project: slotProject))
        h.boot()
        XCTAssertEqual(c.row, "restore.held_guest")
        h.transport.stub("POST", "/auth-service/token/refresh",
                         Stub.session(user: Stub.user(id: "g-held", isAnonymous: true), tokens: Stub.tokens(access: c.accessToken ?? "", refresh: "rt-held-2")))
        let result: Result<SendoraCloudAuthUser, SendoraCloudAuthError> = h.wait { done in h.auth.restoreHeldGuest(completion: done) }
        switch c.verdict {
        case "mismatch":
            guard case .failure(let error) = result else { return XCTFail("\(c.id): must refuse") }
            XCTAssertEqual(error.code, "HELD_GUEST_PROJECT_MISMATCH", c.id)
            XCTAssertEqual(c.errorCode, "HeldGuestProjectMismatch")
            XCTAssertEqual(h.transport.requests(to: "/auth-service/token/refresh").count, 0, "\(c.id): refused CLIENT-SIDE, no network")
            XCTAssertNotNil(h.heldSlot(0), "\(c.id): slot KEPT")
            XCTAssertEqual(h.auth.status(), .signedOut)
        default:
            guard case .success(let user) = result else { return XCTFail("\(c.id): a null slot project is judged on the response, which matches here") }
            XCTAssertEqual(user.id, "g-held")
            XCTAssertEqual(h.auth.status(), .anonymous)
            XCTAssertNil(h.heldSlot(0), "\(c.id): slot released after the install")
        }
    }

    // MARK: Every transition row has a scenario, and every scenario passes

    func test_everyTransitionRowIsReplayed() {
        let scenarios = rowScenarios()
        let fixtureIds = Set(fixture.transitions.map { $0.id })
        XCTAssertEqual(Set(scenarios.keys), fixtureIds, "a fixture row without a Swift scenario (or a stale scenario) — the port must replay the WHOLE table")
        for row in fixture.transitions {
            guard let scenario = scenarios[row.id] else { continue }
            XCTContext.runActivity(named: row.id) { _ in scenario() }
        }
    }

    func test_unspecifiedPairsAreNotClaimedByTheFixture() {
        // The 9 ADR gaps: the port makes a documented choice for each (see
        // CLAUDE.md), and this pins that the fixture still lists them, so the day
        // the ADR adds a row the scenario map above fails loudly.
        let pairs = Set(fixture.unspecifiedByAdr.map { "\($0.from)|\($0.event)" })
        XCTAssertTrue(pairs.contains("unknown|SIGN_OUT"))
        XCTAssertTrue(pairs.contains("signed_out|SIGN_OUT"))
        XCTAssertTrue(pairs.contains("unknown|DELETE"))
    }
}
