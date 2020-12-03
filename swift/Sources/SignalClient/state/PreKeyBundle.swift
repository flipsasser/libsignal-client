//
// Copyright 2020 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

public class PreKeyBundle {
    private var handle: OpaquePointer?

    deinit {
        assertNoError(signal_pre_key_bundle_destroy(handle))
    }

    internal var nativeHandle: OpaquePointer? {
        return handle
    }

    // with a prekey
    public init<Bytes: ContiguousBytes>(registrationId: UInt32,
                                        deviceId: UInt32,
                                        prekeyId: UInt32,
                                        prekey: PublicKey,
                                        signedPrekeyId: UInt32,
                                        signedPrekey: PublicKey,
                                        signedPrekeySignature: Bytes,
                                        identity identityKey: IdentityKey) {
        handle = signedPrekeySignature.withUnsafeBytes {
            var prekeyId = prekeyId
            var result: OpaquePointer?
            assertNoError(signal_pre_key_bundle_new(&result,
                                                    registrationId,
                                                    deviceId,
                                                    &prekeyId,
                                                    prekey.nativeHandle,
                                                    signedPrekeyId,
                                                    signedPrekey.nativeHandle,
                                                    $0.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                    $0.count,
                                                    identityKey.publicKey.nativeHandle))
            return result
        }
    }

    // without a prekey
    public init<Bytes: ContiguousBytes>(registrationId: UInt32,
                                        deviceId: UInt32,
                                        signedPrekeyId: UInt32,
                                        signedPrekey: PublicKey,
                                        signedPrekeySignature: Bytes,
                                        identity identityKey: IdentityKey) {
        handle = signedPrekeySignature.withUnsafeBytes {
            var result: OpaquePointer?
            assertNoError(signal_pre_key_bundle_new(&result,
                                                    registrationId,
                                                    deviceId,
                                                    nil,
                                                    nil,
                                                    signedPrekeyId,
                                                    signedPrekey.nativeHandle,
                                                    $0.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                    $0.count,
                                                    identityKey.publicKey.nativeHandle))
            return result
        }
    }

    public var registrationId: UInt32 {
        return assertNoError {
            try invokeFnReturningInteger {
                signal_pre_key_bundle_get_registration_id(handle, $0)
            }
        }
    }

    public var deviceId: UInt32 {
        return assertNoError {
            try invokeFnReturningInteger {
                signal_pre_key_bundle_get_device_id(handle, $0)
            }
        }
    }

    public var signedPreKeyId: UInt32 {
        return assertNoError {
            try invokeFnReturningInteger {
                signal_pre_key_bundle_get_signed_pre_key_id(handle, $0)
            }
        }
    }

    public var preKeyId: UInt32? {
        let prekey_id = assertNoError {
            try invokeFnReturningInteger {
                signal_pre_key_bundle_get_signed_pre_key_id(handle, $0)
            }
        }

        if prekey_id == 0xFFFFFFFF {
            return nil
        } else {
            return prekey_id
        }
    }

    public var preKeyPublic: PublicKey? {
        return assertNoError {
            try invokeFnReturningOptionalPublicKey {
                signal_pre_key_bundle_get_pre_key_public($0, handle)
            }
        }
    }

    public var identityKey: IdentityKey {
        let pk = assertNoError {
            try invokeFnReturningPublicKey {
                signal_pre_key_bundle_get_identity_key($0, handle)
            }
        }
        return IdentityKey(publicKey: pk)
    }

    public var signedPreKeyPublic: PublicKey {
        return assertNoError {
            try invokeFnReturningPublicKey {
                signal_pre_key_bundle_get_signed_pre_key_public($0, handle)
            }
        }
    }

    public var signedPreKeySignature: [UInt8] {
        return assertNoError {
            try invokeFnReturningArray {
                signal_pre_key_bundle_get_signed_pre_key_signature(handle, $0, $1)
            }
        }
    }
}
