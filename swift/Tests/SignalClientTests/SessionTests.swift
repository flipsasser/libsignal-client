//
// Copyright 2020 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest
import SignalClient

class SessionTests: TestCaseBase {
    fileprivate func initializeSessions(alice_store: InMemorySignalProtocolStore,
                                        bob_store: InMemorySignalProtocolStore,
                                        bob_address: ProtocolAddress) {
        let bob_pre_key = PrivateKey.generate()
        let bob_signed_pre_key = PrivateKey.generate()

        let bob_signed_pre_key_public = bob_signed_pre_key.publicKey.serialize()

        let bob_identity_key = try! bob_store.identityKeyPair(context: nil).identityKey
        let bob_signed_pre_key_signature = try! bob_store.identityKeyPair(context: nil).privateKey.generateSignature(message: bob_signed_pre_key_public)

        let prekey_id: UInt32 = 4570
        let signed_prekey_id: UInt32 = 3006

        let bob_bundle = try! PreKeyBundle(registrationId: bob_store.localRegistrationId(context: nil),
                                           deviceId: 9,
                                           prekeyId: prekey_id,
                                           prekey: bob_pre_key.publicKey,
                                           signedPrekeyId: signed_prekey_id,
                                           signedPrekey: bob_signed_pre_key.publicKey,
                                           signedPrekeySignature: bob_signed_pre_key_signature,
                                           identity: bob_identity_key)

        // Alice processes the bundle:
        try! processPreKeyBundle(bob_bundle,
                                 for: bob_address,
                                 sessionStore: alice_store,
                                 identityStore: alice_store,
                                 context: nil)

        XCTAssertEqual(try! alice_store.loadSession(for: bob_address, context: nil)?.remoteRegistrationId(),
                       try! bob_store.localRegistrationId(context: nil))

        // Bob does the same:
        try! bob_store.storePreKey(PreKeyRecord(id: prekey_id, privateKey: bob_pre_key),
                                   id: prekey_id,
                                   context: nil)

        try! bob_store.storeSignedPreKey(
            SignedPreKeyRecord(
                id: signed_prekey_id,
                timestamp: 42000,
                privateKey: bob_signed_pre_key,
                signature: bob_signed_pre_key_signature
            ),
            id: signed_prekey_id,
            context: nil)
    }

    func testSessionCipher() {
        let alice_address = ProtocolAddress(name: "+14151111111", deviceId: 1)
        let bob_address = ProtocolAddress(name: "+14151111112", deviceId: 1)

        let alice_store = InMemorySignalProtocolStore()
        let bob_store = InMemorySignalProtocolStore()

        initializeSessions(alice_store: alice_store, bob_store: bob_store, bob_address: bob_address)

        // Alice sends a message:
        let ptext_a: [UInt8] = [8, 6, 7, 5, 3, 0, 9]

        let ctext_a = try! signalEncrypt(message: ptext_a,
                                         for: bob_address,
                                         sessionStore: alice_store,
                                         identityStore: alice_store,
                                         context: nil)

        XCTAssertEqual(ctext_a.messageType, .preKey)

        let ctext_b = try! PreKeySignalMessage(bytes: ctext_a.serialize())

        let ptext_b = try! signalDecryptPreKey(message: ctext_b,
                                               from: alice_address,
                                               sessionStore: bob_store,
                                               identityStore: bob_store,
                                               preKeyStore: bob_store,
                                               signedPreKeyStore: bob_store,
                                               context: nil)

        XCTAssertEqual(ptext_a, ptext_b)

        // Bob replies
        let ptext2_b: [UInt8] = [23]

        let ctext2_b = try! signalEncrypt(message: ptext2_b,
                                          for: alice_address,
                                          sessionStore: bob_store,
                                          identityStore: bob_store,
                                          context: nil)

        XCTAssertEqual(ctext2_b.messageType, .whisper)

        let ctext2_a = try! SignalMessage(bytes: ctext2_b.serialize())

        let ptext2_a = try! signalDecrypt(message: ctext2_a,
                                          from: bob_address,
                                          sessionStore: alice_store,
                                          identityStore: alice_store,
                                          context: nil)

        XCTAssertEqual(ptext2_a, ptext2_b)
    }

    func testSealedSenderSession() throws {
        let alice_address = ProtocolAddress(name: "+14151111111", deviceId: 1)
        let bob_address = ProtocolAddress(name: "+14151111112", deviceId: 1)

        let alice_store = InMemorySignalProtocolStore()
        let bob_store = InMemorySignalProtocolStore()

        initializeSessions(alice_store: alice_store, bob_store: bob_store, bob_address: bob_address)

        let trust_root = IdentityKeyPair.generate()
        let server_keys = IdentityKeyPair.generate()
        let server_cert = ServerCertificate(keyId: 1, publicKey: server_keys.publicKey, trustRoot: trust_root.privateKey)
        let sender_addr = SealedSenderAddress(e164: alice_address.name,
                                              uuidString: "9d0652a3-dcc3-4d11-975f-74d61598733f",
                                              deviceId: 1)
        let sender_cert = try! SenderCertificate(sender: sender_addr,
                                                 publicKey: alice_store.identityKeyPair(context: nil).publicKey,
                                                 expiration: 31337,
                                                 signerCertificate: server_cert,
                                                 signerKey: server_keys.privateKey)

        let message = Array("2020 vision".utf8)
        let ciphertext = try sealedSenderEncrypt(message: message,
                                                 for: bob_address,
                                                 from: sender_cert,
                                                 sessionStore: alice_store,
                                                 identityStore: alice_store,
                                                 context: nil)

        let recipient_addr = try! SealedSenderAddress(e164: bob_address.name, uuidString: nil, deviceId: 1)
        let plaintext = try sealedSenderDecrypt(message: ciphertext,
                                                from: recipient_addr,
                                                trustRoot: trust_root.publicKey,
                                                timestamp: 31335,
                                                sessionStore: bob_store,
                                                identityStore: bob_store,
                                                preKeyStore: bob_store,
                                                signedPreKeyStore: bob_store,
                                                context: nil)

        XCTAssertEqual(plaintext.message, message)
        XCTAssertEqual(plaintext.sender, sender_addr)
    }

    static var allTests: [(String, (SessionTests) -> () throws -> Void)] {
        return [
            ("testSessionCipher", testSessionCipher),
            ("testSealedSenderSession", testSealedSenderSession),
        ]
    }
}
