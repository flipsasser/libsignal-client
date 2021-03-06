//
// Copyright 2020 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

public class InMemorySignalProtocolStore: IdentityKeyStore, PreKeyStore, SignedPreKeyStore, SessionStore, SenderKeyStore {
    private var publicKeys: [ProtocolAddress: IdentityKey] = [:]
    private var privateKey: IdentityKeyPair
    private var deviceId: UInt32
    private var prekeyMap: [UInt32: PreKeyRecord] = [:]
    private var signedPrekeyMap: [UInt32: SignedPreKeyRecord] = [:]
    private var sessionMap: [ProtocolAddress: SessionRecord] = [:]
    private var senderKeyMap: [SenderKeyName: SenderKeyRecord] = [:]

    public init() throws {
        privateKey = try IdentityKeyPair.generate()
        deviceId = UInt32.random(in: 0...65535)
    }

    public init(identity: IdentityKeyPair, deviceId: UInt32) {
        self.privateKey = identity
        self.deviceId = deviceId
    }

    public func identityKeyPair(context: UnsafeMutableRawPointer?) throws -> IdentityKeyPair {
        return privateKey
    }

    public func localRegistrationId(context: UnsafeMutableRawPointer?) throws -> UInt32 {
        return deviceId
    }

    public func saveIdentity(_ identity: IdentityKey, for address: ProtocolAddress, context: UnsafeMutableRawPointer?) throws -> Bool {
        if publicKeys.updateValue(identity, forKey: address) == nil {
            return false; // newly created
        } else {
            return true
        }
    }

    public func isTrustedIdentity(_ identity: IdentityKey, for address: ProtocolAddress, direction: Direction, context: UnsafeMutableRawPointer?) throws -> Bool {
        if let pk = publicKeys[address] {
            return pk == identity
        } else {
            return true // tofu
        }
    }

    public func identity(for address: ProtocolAddress, context: UnsafeMutableRawPointer?) throws -> IdentityKey? {
        return publicKeys[address]
    }

    public func loadPreKey(id: UInt32, context: UnsafeMutableRawPointer?) throws -> PreKeyRecord {
        if let record = prekeyMap[id] {
            return record
        } else {
            throw SignalError.invalidKeyIdentifier("no prekey with this identifier")
        }
    }

    public func storePreKey(_ record: PreKeyRecord, id: UInt32, context: UnsafeMutableRawPointer?) throws {
        prekeyMap[id] = record
    }

    public func removePreKey(id: UInt32, context: UnsafeMutableRawPointer?) throws {
        prekeyMap.removeValue(forKey: id)
    }

    public func loadSignedPreKey(id: UInt32, context: UnsafeMutableRawPointer?) throws -> SignedPreKeyRecord {
        if let record = signedPrekeyMap[id] {
            return record
        } else {
            throw SignalError.invalidKeyIdentifier("no signed prekey with this identifier")
        }
    }

    public func storeSignedPreKey(_ record: SignedPreKeyRecord, id: UInt32, context: UnsafeMutableRawPointer?) throws {
        signedPrekeyMap[id] = record
    }

    public func loadSession(for address: ProtocolAddress, context: UnsafeMutableRawPointer?) throws -> SessionRecord? {
        return sessionMap[address]
    }

    public func storeSession(_ record: SessionRecord, for address: ProtocolAddress, context: UnsafeMutableRawPointer?) throws {
        sessionMap[address] = record
    }

    public func storeSenderKey(name: SenderKeyName, record: SenderKeyRecord, context: UnsafeMutableRawPointer?) throws {
        senderKeyMap[name] = record
    }

    public func loadSenderKey(name: SenderKeyName, context: UnsafeMutableRawPointer?) throws -> SenderKeyRecord? {
        return senderKeyMap[name]
    }
}
