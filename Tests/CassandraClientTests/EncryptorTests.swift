//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift Cassandra Client open source project
//
// Copyright (c) 2022-2025 Apple Inc. and the Swift Cassandra Client project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Swift Cassandra Client project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import XCTest

@testable import CassandraClient

@available(macOS 11.0, *)
final class EncryptorTests: XCTestCase {
    // Helper: generate a random 32-byte key
    private func randomKey() -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        for i in 0 ..< bytes.count {
            bytes[i] = UInt8.random(in: 0 ... 255)
        }
        return Data(bytes)
    }

    // Helper: create a simple context for testing
    private func testContext(column: String = "ssn", primaryKey: Data? = nil) -> CassandraClient.EncryptionContext {
        CassandraClient.EncryptionContext(
            keyspace: "test_keyspace",
            table: "users",
            column: column,
            primaryKey: primaryKey ?? Data("row-1".utf8)
        )
    }

    // Helper: create an encryptor with one key
    private func makeEncryptor(keyName: String = "key-1", key: Data? = nil) throws -> (CassandraClient.Encryptor, Data) {
        let keyData = key ?? randomKey()
        let encryptor = try CassandraClient.Encryptor(
            keyMap: [keyName: keyData],
            currentKeyName: keyName
        )
        return (encryptor, keyData)
    }

    // MARK: - Encrypt / Decrypt

    /// Encrypt then decrypt should return the original plaintext.
    func testEncryptDecrypt() throws {
        let (encryptor, _) = try makeEncryptor()
        let context = testContext()
        let plaintext = Data("hello-world!".utf8)

        let encrypted = try encryptor.encrypt(plaintext, context: context)
        let decrypted = try encryptor.decrypt(encrypted, context: context)

        XCTAssertEqual(decrypted, plaintext)
        XCTAssertNotEqual(encrypted, plaintext, "Encrypted data should differ from plaintext")
    }

    /// Same plaintext encrypted for different columns should produce different ciphertext.
    func testContextBinding() throws {
        let (encryptor, _) = try makeEncryptor()
        let plaintext = Data("secret-value".utf8)
        let primaryKey = Data("row-1".utf8)

        let ssnContext = testContext(column: "ssn", primaryKey: primaryKey)
        let ccContext = testContext(column: "credit_card", primaryKey: primaryKey)

        let encryptedSSN = try encryptor.encrypt(plaintext, context: ssnContext)
        let encryptedCC = try encryptor.encrypt(plaintext, context: ccContext)

        XCTAssertNotEqual(encryptedSSN, encryptedCC, "Different columns should produce different ciphertext")
    }

    /// Same plaintext encrypted for different rows should produce different ciphertext.
    func testRowBinding() throws {
        let (encryptor, _) = try makeEncryptor()
        let plaintext = Data("secret-value".utf8)

        let context1 = testContext(primaryKey: Data("row-1".utf8))
        let context2 = testContext(primaryKey: Data("row-2".utf8))

        let encrypted1 = try encryptor.encrypt(plaintext, context: context1)
        let encrypted2 = try encryptor.encrypt(plaintext, context: context2)

        XCTAssertNotEqual(encrypted1, encrypted2, "Different primary keys should produce different ciphertext")
    }

    // MARK: - Key Rotation

    /// Encrypt with key-1, add key-2, switch to key-2, old data still decrypts.
    func testKeyRotation() throws {
        let (encryptor, _) = try makeEncryptor(keyName: "key-1")
        let context = testContext()
        let plaintext = Data("secret-data".utf8)

        let encryptedWithKey1 = try encryptor.encrypt(plaintext, context: context)

        try encryptor.addKey(name: "key-2", secret: randomKey())
        try encryptor.setCurrentKeyName("key-2")

        let encryptedWithKey2 = try encryptor.encrypt(plaintext, context: context)

        // Both should decrypt correctly
        let decrypted1 = try encryptor.decrypt(encryptedWithKey1, context: context)
        let decrypted2 = try encryptor.decrypt(encryptedWithKey2, context: context)

        XCTAssertEqual(decrypted1, plaintext)
        XCTAssertEqual(decrypted2, plaintext)
    }

    // MARK: - Tamper Detection

    /// Flipping a byte in the ciphertext should cause decryption to fail.
    func testTamperDetection() throws {
        let (encryptor, _) = try makeEncryptor()
        let context = testContext()
        let plaintext = Data("hello-world!".utf8)

        var encrypted = try encryptor.encrypt(plaintext, context: context)

        // Flip a byte near the end (in the ciphertext region)
        let tamperIndex = encrypted.count - 20
        encrypted[tamperIndex] ^= 0xFF

        XCTAssertThrowsError(try encryptor.decrypt(encrypted, context: context))
    }
}
