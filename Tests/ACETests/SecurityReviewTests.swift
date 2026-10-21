//
//  SecurityReviewTests.swift
//  ACE SDK
//
//  The 2026-10-21 security review decisions (docs/review-2026-10-21-security.md): C3, C4, C7–C11 and the sdk-swift items.
//

import Foundation
import Testing
@testable import ACE

@Suite struct SecurityReviewTests {
    /// An identity operation without `now` reads the system clock as any other clock: an out-of-range reading is
    /// `invalid_argument`, never a timestamp.
    @Test func identityNowValidatesTheClockReading() throws {
        expectCode(.invalidArgument) { try identityNow(nil, clock: { -1 }) }
        expectCode(.invalidArgument) { try identityNow(nil, clock: { 1 << 53 }) }
        #expect(try identityNow(nil, clock: { 42 }) == 42)
        #expect(try identityNow(7) == 7)
    }
}
