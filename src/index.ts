import { createDebug } from '@bicycle-codes/debug'
import libsodium from 'libsodium-wrappers'
import {
    supportsWebAuthn,
    toBase64String,
    normalizeCredentialsList,
    toUTF8String,
    parsePublicKeySPKI,
    parseAuthenticatorData,
    checkRPID,
    getPublicKeyOpts,
    buildPasskeyEntry,
    credentialTypeKey,
    resetAbortReason,
    localIdentities,
    storeLocalIdentities,
    pushLocalIdentity
} from './util'
import type { Identity, RegistrationResult, LockKey } from './types'
import * as cbor from 'cborg'
const debug = createDebug()

export { localIdentities, storeLocalIdentities, pushLocalIdentity }

await libsodium.ready
const sodium = libsodium

// const externalSignalCache = new WeakMap()
const IV_BYTE_LENGTH = sodium.crypto_sign_SEEDBYTES
const CURRENT_LOCK_KEY_FORMAT_VERSION = 1

/**
 * simple
 * - can register a new user ID
 * - can get an existing keypair via webauthn auth
 * That means we need to store a collection of existing users.
 * This would be users that use this machine.
 *   This means a correlation between username & biometric auth.
 */

export async function registerLocalIdentity (
    localID = toBase64String(generateEntropy(15)),
    lockKey = deriveLockKey(),
    _opts:Partial<{
        username:string
        displayName:string
        relyingPartyID:string
        relyingPartyName:string
    }> = {
        username: 'local-user',
        displayName: 'Local User',
        relyingPartyID: document.location.hostname,
        relyingPartyName: 'wacg'
    }
):Promise<{ record:Identity, keys }> {
    const abortToken = new AbortController()
    const opts = Object.assign({
        username: 'local-user',
        displayName: 'Local User',
        relyingPartyID: document.location.hostname,
        relyingPartyName: 'wacg'
    }, _opts)
    const { username, displayName, relyingPartyID, relyingPartyName } = opts

    let result:{ record:Identity, keys }
    try {
        const identityRecord = (await localIdentities())[localID]
        const lastSeq = ((identityRecord || {}).lastSeq || 0) + 1

        /**
         * @note
         * encode the userHandle field of the passkey with the
         * first 32 bytes of the keypair IV, and then 2 bytes
         * to encode (big-endian) a passkey sequence value; this
         * additional value allows multiple passkeys (up to 65,535 of
         * them) registered on the same authenticator, sharing the same
         * keypair IV in its userHandle
         */
        const userHandle = new Uint8Array(lockKey.iv.byteLength + 2)
        const seqBytes = new DataView(new ArrayBuffer(2))
        seqBytes.setInt16(0, lastSeq, /* littleEndian= */false)
        userHandle.set(lockKey.iv, 0)
        userHandle.set(new Uint8Array(seqBytes.buffer), lockKey.iv.byteLength)

        const opts = {
            signal: abortToken.signal,
            publicKey: getPublicKeyOpts({
                relyingPartyID,
                relyingPartyName,
                username,
                userID: userHandle,
                usernameDisplay: displayName
            }),
        }

        // internal meta-data only
        Object.defineProperty(
            opts,
            credentialTypeKey,
            {
                enumerable: false,
                writable: false,
                configurable: false,
                value: 'publicKey'
            }
        )

        // set the `iv` as userID here
        const registrationResult = await register(opts, { relyingPartyID })

        if (registrationResult !== null) {
            result = {
                record: {
                    lastSeq,
                    passkeys: [
                        buildPasskeyEntry({
                            seq: lastSeq,
                            credentialID: registrationResult.response.credentialID,
                            publicKey: registrationResult.response.publicKey,
                        }),
                    ],
                },
                keys: lockKey,
            }

            await pushLocalIdentity(localID, result.record)
        }
    } catch (err) {
        throw new Error('Identity/Passkey registration failed', { cause: err })
    }

    return result!
}

function deriveLockKey (iv = generateEntropy(IV_BYTE_LENGTH)):LockKey {
    try {
        const ed25519KeyPair = sodium.crypto_sign_seed_keypair(iv)

        return {
            keyFormatVersion: CURRENT_LOCK_KEY_FORMAT_VERSION,
            iv,
            publicKey: ed25519KeyPair.publicKey,
            privateKey: ed25519KeyPair.privateKey,
            encPK: sodium.crypto_sign_ed25519_pk_to_curve25519(
                ed25519KeyPair.publicKey,
            ),
            encSK: sodium.crypto_sign_ed25519_sk_to_curve25519(
                ed25519KeyPair.privateKey,
            ),
        }
    } catch (err) {
        throw new Error('Encryption/decryption key derivation failed.', {
            cause: err,
        })
    }
}

function generateEntropy (numBytes = 16) {
    return sodium.randombytes_buf(numBytes)
}

async function register (regOptions:CredentialCreationOptions, opts:{
    relyingPartyID:string,
}):Promise<RegistrationResult> {
    const { relyingPartyID } = opts

    let res:RegistrationResult
    try {
        if (!(await supportsWebAuthn())) {
            throw new Error('WebAuthentication not supported on this device')
        }

        const regOpt = regOptions[credentialTypeKey]
        debug('reg opt', regOpt)
        debug('reg opt exclude', regOpt.excludeCredentials)

        // ensure credential IDs are binary (not base64 string)
        regOptions[regOptions[credentialTypeKey]].excludeCredentials = (
            normalizeCredentialsList(
                regOptions[regOptions[credentialTypeKey]].excludeCredentials
            )
        )

        const regResult = (await navigator.credentials
            .create(regOptions)) as PublicKeyCredential

        const response = regResult!.response as AuthenticatorAttestationResponse
        const regClientDataRaw = new Uint8Array(
            regResult!.response.clientDataJSON
        )

        const regClientData = JSON.parse(toUTF8String(regClientDataRaw))
        if (regClientData.type !== 'webauthn.create') {
            throw new Error('Invalid registration response')
        }
        const expectedChallenge = sodium.to_base64(
            regOptions[regOptions[credentialTypeKey]].challenge,
            sodium.base64_variants.URLSAFE_NO_PADDING
        )
        if (regClientData.challenge !== expectedChallenge) {
            throw new Error('Challenge not accepted')
        }

        const publicKeyAlgoCOSE = response.getPublicKeyAlgorithm()
        const publicKeySPKI = new Uint8Array(response.getPublicKey()!)
        const {
            algo: publicKeyAlgoOID,
            raw: publicKeyRaw,
        } = parsePublicKeySPKI(publicKeySPKI)

        const regAuthDataRaw = (
            typeof response.getAuthenticatorData !== 'undefined' ?
                (new Uint8Array(response.getAuthenticatorData())) :

                cbor.decode(
                    new Uint8Array(response.attestationObject)
                ).authData
        )

        const regAuthData = parseAuthenticatorData(
            regAuthDataRaw
        ) as Partial<ReturnType<typeof parseAuthenticatorData>>

        if (!checkRPID(regAuthData.rpIdHash, relyingPartyID)) {
            throw new Error('Unexpected relying-party ID')
        }

        // sign-count not supported by this authenticator?
        if (regAuthData.signCount === 0) {
            delete regAuthData.signCount
        }

        res = {
            request: {
                credentialType: regResult.type,
                ...regOptions[regOptions[credentialTypeKey]],

                challenge: toBase64String(
                    regOptions[regOptions[credentialTypeKey]].challenge
                ),
                ...(Object.fromEntries(
                    Object.entries(regClientData).filter(([key]) => (
                        ['origin', 'crossOrigin',].includes(key)
                    ))
                )),
            },

            response: {
                credentialID: toBase64String(new Uint8Array(regResult.rawId)),
                credentialType: regResult.type,
                authenticatorAttachment: regResult.authenticatorAttachment,
                publicKey: {
                    algoCOSE: publicKeyAlgoCOSE,
                    algoOID: publicKeyAlgoOID,
                    spki: publicKeySPKI,
                    raw: publicKeyRaw!,
                },
                ...(Object.fromEntries(
                    Object.entries(regAuthData).filter(([key]) => (
                        ['flags', 'signCount', 'userPresence',
                            'userVerification'].includes(key)
                    ))
                )),
                raw: regResult.response,
            },
        }
    } catch (err) {
        if (err !== resetAbortReason) {
            throw new Error('Credential registration failed', { cause: err, })
        }
    }

    return res!
}

// function cleanupExternalSignalHandler (token:AbortController) {
//     // controller previously attached to an
//     // external abort-signal?
//     if (token !== null && externalSignalCache.has(token)) {
//         const [prevExternalSignal, handlerFn] = externalSignalCache.get(token)
//         prevExternalSignal.removeEventListener('abort', handlerFn)
//         externalSignalCache.delete(token)
//     }
// }

// function resetAbortToken (
//     abortToken:AbortController,
//     externalSignal:AbortController
// ) {
//     // previous attempt still pending?
//     if (abortToken) {
//         cleanupExternalSignalHandler(abortToken)

//         if (!abortToken.signal.aborted) {
//             abortToken.abort('Passkey operation abandoned.')
//         }
//     }
//     abortToken = new AbortController()

//     // new external abort-signal passed in, to chain
//     // off of?
//     if (externalSignal !== null) {
//         // signal already aborted?
//         if (externalSignal.signal.aborted) {
//             abortToken.abort(externalSignal.signal.reason)
//         }
//         // listen to future abort-signal
//         else {
//             let handlerFn = () => {
//                 cleanupExternalSignalHandler(abortToken)
//                 abortToken.abort(externalSignal.reason)
//                 abortToken = externalSignal = handlerFn = null
//             }
//             externalSignal.addEventListener('abort', handlerFn)
//             externalSignalCache.set(abortToken, [externalSignal, handlerFn,])
//         }
//     }
// }
