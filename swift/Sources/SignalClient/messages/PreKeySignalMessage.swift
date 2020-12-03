//
// Copyright 2020 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

public class PreKeySignalMessage {
    private var handle: OpaquePointer?

    deinit {
        assertNoError(signal_pre_key_signal_message_destroy(handle))
    }

    public init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        handle = try bytes.withUnsafeBytes {
            var result: OpaquePointer?
            try checkError(signal_pre_key_signal_message_deserialize(&result, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count))
            return result
        }
    }

    public init(version: UInt8,
                registrationId: UInt32,
                preKeyId: UInt32?,
                signedPreKeyId: UInt32,
                baseKey: PublicKey,
                identityKey: PublicKey,
                message: SignalMessage) {

        var preKeyId = preKeyId ?? 0xFFFFFFFF

        assertNoError(signal_pre_key_signal_message_new(&handle,
                                                        version,
                                                        registrationId,
                                                        &preKeyId,
                                                        signedPreKeyId,
                                                        baseKey.nativeHandle,
                                                        identityKey.nativeHandle,
                                                        message.nativeHandle))
    }

    public func serialize() -> [UInt8] {
        return assertNoError {
            try invokeFnReturningArray {
                signal_pre_key_signal_message_serialize(handle, $0, $1)
            }
        }
    }

    public var version: UInt32 {
        return assertNoError {
            try invokeFnReturningInteger {
                signal_pre_key_signal_message_get_version(handle, $0)
            }
        }
    }

    public var registrationId: UInt32 {
        return assertNoError {
            try invokeFnReturningInteger {
                signal_pre_key_signal_message_get_registration_id(handle, $0)
            }
        }
    }

    public var preKeyId: UInt32? {
        let id = assertNoError {
            try invokeFnReturningInteger {
                signal_pre_key_signal_message_get_pre_key_id(handle, $0)
            }
        }

        if id == 0xFFFFFFFF {
            return nil
        } else {
            return id
        }
    }

    public var signedPreKeyId: UInt32 {
        return assertNoError {
            try invokeFnReturningInteger {
                signal_pre_key_signal_message_get_signed_pre_key_id(handle, $0)
            }
        }
    }

    public var baseKey: PublicKey {
        return assertNoError {
            try invokeFnReturningPublicKey {
                signal_pre_key_signal_message_get_base_key($0, handle)
            }
        }
    }

    public var identityKey: PublicKey {
        return assertNoError {
            try invokeFnReturningPublicKey {
                signal_pre_key_signal_message_get_identity_key($0, handle)
            }
        }
    }

    public var signalMessage: SignalMessage {
        var m: OpaquePointer?
        assertNoError(signal_pre_key_signal_message_get_signal_message(&m, handle))
        return SignalMessage(owned: m)
    }

    internal var nativeHandle: OpaquePointer? {
        return handle
    }
}
