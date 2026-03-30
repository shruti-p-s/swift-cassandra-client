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

    // MARK: - Type-specific roundtrips

    /// Encrypt and decrypt Int32.
    func testInt32Roundtrip() throws {
        let (encryptor, _) = try makeEncryptor()
        let context = testContext(column: "age")
        let value: Int32 = -42
        var bigEndian = value.bigEndian
        let data = Data(bytes: &bigEndian, count: 4)
        let encrypted = try encryptor.encrypt(data, context: context)
        let decrypted = try encryptor.decrypt(encrypted, context: context)
        XCTAssertEqual(decrypted.count, 4)
        let result = decrypted.withUnsafeBytes { $0.load(as: Int32.self).bigEndian }
        XCTAssertEqual(result, value)
    }

    /// Encrypt and decrypt Int64.
    func testInt64Roundtrip() throws {
        let (encryptor, _) = try makeEncryptor()
        let context = testContext(column: "age64")
        let value: Int64 = 9_876_543_210
        var bigEndian = value.bigEndian
        let data = Data(bytes: &bigEndian, count: 8)
        let encrypted = try encryptor.encrypt(data, context: context)
        let decrypted = try encryptor.decrypt(encrypted, context: context)
        XCTAssertEqual(decrypted.count, 8)
        let result = decrypted.withUnsafeBytes { $0.load(as: Int64.self).bigEndian }
        XCTAssertEqual(result, value)
    }

    /// Encrypt and decrypt Double.
    func testDoubleRoundtrip() throws {
        let (encryptor, _) = try makeEncryptor()
        let context = testContext(column: "score")
        let value: Double = 3.14159
        var bits = value.bitPattern.bigEndian
        let data = Data(bytes: &bits, count: 8)
        let encrypted = try encryptor.encrypt(data, context: context)
        let decrypted = try encryptor.decrypt(encrypted, context: context)
        XCTAssertEqual(decrypted.count, 8)
        let result = Double(bitPattern: decrypted.withUnsafeBytes { $0.load(as: UInt64.self).bigEndian })
        XCTAssertEqual(result, value)
    }

    /// Encrypt and decrypt UUID.
    func testUUIDRoundtrip() throws {
        let (encryptor, _) = try makeEncryptor()
        let context = testContext(column: "uid")
        let value = Foundation.UUID()
        let u = value.uuid
        let data = Data([u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7,
                          u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15])
        let encrypted = try encryptor.encrypt(data, context: context)
        let decrypted = try encryptor.decrypt(encrypted, context: context)
        XCTAssertEqual(decrypted.count, 16)
        let t: uuid_t = (decrypted[0], decrypted[1], decrypted[2], decrypted[3],
                          decrypted[4], decrypted[5], decrypted[6], decrypted[7],
                          decrypted[8], decrypted[9], decrypted[10], decrypted[11],
                          decrypted[12], decrypted[13], decrypted[14], decrypted[15])
        XCTAssertEqual(Foundation.UUID(uuid: t), value)
    }

    /// Encrypt and decrypt raw bytes.
    func testBytesRoundtrip() throws {
        let (encryptor, _) = try makeEncryptor()
        let context = testContext(column: "blob")
        let value: [UInt8] = [0x00, 0xFF, 0x42, 0xAB, 0x01]
        let encrypted = try encryptor.encrypt(Data(value), context: context)
        let decrypted = try encryptor.decrypt(encrypted, context: context)
        XCTAssertEqual(Array(decrypted), value)
    }

    // MARK: - Invalid envelope

    /// Envelope too short to contain even the header fields.
    func testEnvelopeTooShort() throws {
        let (encryptor, _) = try makeEncryptor()
        let context = testContext()
        let tooShort = Data([0x01, 0x02, 0x03])
        XCTAssertThrowsError(try encryptor.decrypt(tooShort, context: context))
    }

    /// Envelope with wrong version byte.
    func testEnvelopeWrongVersion() throws {
        let (encryptor, _) = try makeEncryptor()
        let context = testContext()
        var envelope = try encryptor.encrypt(Data("hello".utf8), context: context)
        envelope[0] = 0xFF  // corrupt version byte
        XCTAssertThrowsError(try encryptor.decrypt(envelope, context: context))
    }

    /// Envelope with wrong algorithm byte.
    func testEnvelopeWrongAlgorithm() throws {
        let (encryptor, _) = try makeEncryptor()
        let context = testContext()
        var envelope = try encryptor.encrypt(Data("hello".utf8), context: context)
        envelope[1] = 0xFF  // corrupt algorithm byte
        XCTAssertThrowsError(try encryptor.decrypt(envelope, context: context))
    }

    // MARK: - Missing key

    /// Decrypt with an encryptor that doesn't have the key used to encrypt.
    func testMissingKey() throws {
        let (encryptor1, _) = try makeEncryptor(keyName: "key-1")
        let context = testContext()
        let encrypted = try encryptor1.encrypt(Data("secret".utf8), context: context)

        // Create a second encryptor with a different key name
        let (encryptor2, _) = try makeEncryptor(keyName: "key-2")
        XCTAssertThrowsError(try encryptor2.decrypt(encrypted, context: context))
    }

    // MARK: - Key validation

    /// Empty key name should be rejected.
    func testEmptyKeyName() {
        XCTAssertThrowsError(try CassandraClient.Encryptor(
            keyMap: ["": randomKey()],
            currentKeyName: ""
        ))
    }

    /// Key name with invalid characters should be rejected.
    func testInvalidKeyNameCharacters() {
        XCTAssertThrowsError(try CassandraClient.Encryptor(
            keyMap: ["key with spaces": randomKey()],
            currentKeyName: "key with spaces"
        ))
    }

    /// Key that is not 32 bytes should be rejected.
    func testWrongKeySize() {
        XCTAssertThrowsError(try CassandraClient.Encryptor(
            keyMap: ["key-1": Data([0x01, 0x02, 0x03])],
            currentKeyName: "key-1"
        ))
    }

    // MARK: - Empty plaintext

    /// Encrypt and decrypt empty data.
    func testEmptyPlaintext() throws {
        let (encryptor, _) = try makeEncryptor()
        let context = testContext()
        let encrypted = try encryptor.encrypt(Data(), context: context)
        let decrypted = try encryptor.decrypt(encrypted, context: context)
        XCTAssertEqual(decrypted, Data())
    }

    // MARK: - Wrong context

    /// Decrypt with a different primaryKey should fail (AES-GCM auth error).
    func testWrongContext() throws {
        let (encryptor, _) = try makeEncryptor()
        let contextA = testContext(primaryKey: Data("row-1".utf8))
        let contextB = testContext(primaryKey: Data("row-2".utf8))
        let encrypted = try encryptor.encrypt(Data("secret".utf8), context: contextA)
        XCTAssertThrowsError(try encryptor.decrypt(encrypted, context: contextB))
    }
}
