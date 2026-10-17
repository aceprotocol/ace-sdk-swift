//
//  Utils.swift
//  ACE SDK
//
//  HTTP helpers.
//

import Foundation

/// The lowercased media type of `Content-Type`, without parameters ("" when absent).
package func mediaType(_ response: HTTPURLResponse) -> String {
    (response.value(forHTTPHeaderField: "Content-Type") ?? "")
        .split(separator: ";", maxSplits: 1).first.map { $0.trimmingCharacters(in: .whitespaces).lowercased() } ?? ""
}
