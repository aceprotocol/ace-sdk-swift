//
//  Keccak256.swift
//  ACE SDK
//
//  Pure Swift implementation of Keccak-256 (Ethereum's hash function).
//  Keccak-256, NOT NIST SHA-3-256 — padding byte 0x01 vs 0x06.
//

import Foundation

enum Keccak256 {

    /// Compute Keccak-256 hash of input data
    static func hash(_ data: Data) -> Data {
        let rate = 136
        var state = [UInt64](repeating: 0, count: 25)

        var input = [UInt8](data)
        input.append(0x01)
        let rem = input.count % rate
        if rem != 0 {
            input.append(contentsOf: [UInt8](repeating: 0, count: rate - rem))
        }
        input[input.count - 1] |= 0x80

        let blocks = input.count / rate
        for block in 0..<blocks {
            let offset = block * rate
            for lane in 0..<(rate / 8) {
                let i = offset + lane * 8
                var word: UInt64 = UInt64(input[i])
                word |= UInt64(input[i + 1]) << 8
                word |= UInt64(input[i + 2]) << 16
                word |= UInt64(input[i + 3]) << 24
                word |= UInt64(input[i + 4]) << 32
                word |= UInt64(input[i + 5]) << 40
                word |= UInt64(input[i + 6]) << 48
                word |= UInt64(input[i + 7]) << 56
                state[lane] ^= word
            }
            keccakF(&state)
        }

        var result = Data(capacity: 32)
        for lane in 0..<4 {
            var word = state[lane]
            for _ in 0..<8 {
                result.append(UInt8(word & 0xFF))
                word >>= 8
            }
        }
        return result
    }

    // MARK: - Keccak-f[1600] Permutation

    private static func keccakF(_ a: inout [UInt64]) {
        var c = [UInt64](repeating: 0, count: 5)
        var d = [UInt64](repeating: 0, count: 5)
        var b = [UInt64](repeating: 0, count: 25)

        for round in 0..<24 {
            for x in 0..<5 {
                c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20]
            }
            for x in 0..<5 {
                d[x] = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1)
            }
            for i in 0..<25 { a[i] ^= d[i % 5] }

            for i in 0..<25 { b[pi[i]] = rotl(a[i], rho[i]) }

            for y in 0..<5 {
                let o = y * 5
                for x in 0..<5 {
                    a[o + x] = b[o + x] ^ (~b[o + (x + 1) % 5] & b[o + (x + 2) % 5])
                }
            }

            a[0] ^= rc[round]
        }
    }

    @inline(__always)
    private static func rotl(_ x: UInt64, _ n: Int) -> UInt64 {
        n == 0 ? x : (x << n) | (x >> (64 - n))
    }

    private static let rc: [UInt64] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]

    private static let rho: [Int] = [
         0,  1, 62, 28, 27, 36, 44,  6, 55, 20,
         3, 10, 43, 25, 39, 41, 45, 15, 21,  8,
        18,  2, 61, 56, 14,
    ]

    private static let pi: [Int] = [
         0, 10, 20,  5, 15, 16,  1, 11, 21,  6,
         7, 17,  2, 12, 22, 23,  8, 18,  3, 13,
        14, 24,  9, 19,  4,
    ]
}
