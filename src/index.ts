import store from '@lo-fi/client-storage/idb'
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
    packPublicKeyJSON,
    unpackPublicKeyJSON,
    credentialTypeKey,
    resetAbortReason
} from './util'
import type { Identity, Passkey, RegistrationResult } from './types'
import * as cbor from 'cborg'
const debug = createDebug()

await libsodium.ready
const sodium = libsodium

const localIdentities = await loadLocalIdentities()
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
    opts:{
        username:string
        displayName:string
        relyingPartyID:string
        relyingPartyName:string
    } = {
        username: 'local-user',
        displayName: 'Local User',
        relyingPartyID: document.location.hostname,
        relyingPartyName: 'wacg'
    }
) {
    debug('lock key', lockKey)
    const abortToken = new AbortController()
    const { username, displayName, relyingPartyID, relyingPartyName } = opts

    try {
        const identityRecord = localIdentities[localID]
        const lastSeq = ((identityRecord || {}).lastSeq || 0) + 1

        // note: encode the userHandle field of the passkey with the
        // first 32 bytes of the keypair IV, and then 2 bytes
        // to encode (big-endian) a passkey sequence value; this
        // additional value allows multiple passkeys (up to 65,535 of
        // them) registered on the same authenticator, sharing the same
        // lock-keypair IV in its userHandle
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
            return {
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
                lockKey,
            }
        }
    } catch (err) {
        throw new Error('Identity/Passkey registration failed', { cause: err, })
    }
}

function deriveLockKey (iv = generateEntropy(IV_BYTE_LENGTH)) {
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

async function loadLocalIdentities ():Promise<Record<string, Identity>> {
    return (
        Object.fromEntries(
            Object.entries<Identity>(
                (await store.get('local-identities')) || {}
            )
                // only accept well-formed local-identity entries
                .filter((id:[string, Identity]) => {
                    const [, entry] = id

                    return (
                        typeof entry.lastSeq === 'number' &&
                        Array.isArray(entry.passkeys) &&
                        entry.passkeys.length > 0 &&
                        entry.passkeys.every(passkey => (
                            typeof passkey.credentialID === 'string' &&
                            passkey.credentialID !== '' &&
                            typeof passkey.seq === 'number' &&
                            passkey.publicKey != null &&
                            typeof passkey.publicKey === 'object' &&
                            typeof passkey.publicKey.algoCOSE === 'number' &&
                            typeof passkey.publicKey.raw === 'string' &&
                            passkey.publicKey.raw !== '' &&
                            typeof passkey.publicKey.spki === 'string' &&
                            passkey.publicKey.spki !== '' &&
                            typeof passkey.hash === 'string' &&
                            passkey.hash !== '' &&
                            passkey.hash === computePasskeyEntryHash(passkey)
                        ))
                    )
                })
                // unpack passkey public-keys
                .map(([localID, entry,]) => ([
                    localID,
                    {
                        ...entry,
                        passkeys: entry.passkeys.map(passkey => ({
                            ...passkey,
                            publicKey: unpackPublicKeyJSON(passkey.publicKey),
                        }))
                    },
                ]))
        )
    )
}

function computePasskeyEntryHash (passkeyEntry:Passkey) {
    const { hash: _, ...passkey } = passkeyEntry
    return toBase64String(sodium.crypto_hash(JSON.stringify({
        ...passkey,
        publicKey: packPublicKeyJSON(passkey.publicKey),
    })))
}

async function register (regOptions:CredentialCreationOptions, opts:{
    relyingPartyID:string,
}):Promise<RegistrationResult> {
    debug('reg options', regOptions)
    const { relyingPartyID } = opts

    let res:RegistrationResult
    try {
        if (!(await supportsWebAuthn())) {
            throw new Error('WebAuthentication not supported on this device')
        }

        const regOpt = regOptions[credentialTypeKey]
        debug('credential type key', credentialTypeKey)
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
                    raw: publicKeyRaw,
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
