import { store } from '@lo-fi/client-storage/idb'
import { createDebug } from '@bicycle-codes/debug'
import sodium from 'libsodium'
import { publicKeyAlgorithms } from './constants'
// import * as cbor from 'cborg'
const debug = createDebug()

const localIdentities = await loadLocalIdentities()
const IV_BYTE_LENGTH = sodium.crypto_sign_SEEDBYTES
const CURRENT_LOCK_KEY_FORMAT_VERSION = 1

export async function registerLocalIdentity (
    localID = toBase64String(generateEntropy(15)),
    lockKey = deriveLockKey(),
    {
        relyingPartyID = document.location.hostname,
        relyingPartyName = 'Local Data Lock',
        username = 'local-user',
        displayName = 'Local User',
    }
) {
    debug('lock key', lockKey)

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

        const regOptions = regDefaults({
            relyingPartyID,
            relyingPartyName,
            user: {
                id: userHandle,
                name: username,
                displayName,
            },
            signal: abortToken.signal,
        })
        const regResult = await register(regOptions)

        if (regResult != null) {
            return {
                record: {
                    lastSeq,
                    passkeys: [
                        buildPasskeyEntry({
                            seq: lastSeq,
                            credentialID: regResult.response.credentialID,
                            publicKey: regResult.response.publicKey,
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
        throw new Error('Encryption/decryption key derivation failed.', { cause: err, })
    }
}

function generateEntropy (numBytes = 16) {
    return sodium.randombytes_buf(numBytes)
}

interface PassKeyPublicKey {
    algoCOSE:number;
    raw:string;
    spki:string;
}

interface Passkey {
    credentialID:string;
    seq:number;
    publicKey:PassKeyPublicKey;
    hash:string;
}

interface Identity {
    lastSeq:number;
    passkeys:Passkey[];
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

function unpackPublicKeyJSON (publicKeyEntryJSON:PassKeyPublicKey) {
    const publicKeyEntry = (
        typeof publicKeyEntryJSON === 'string' ?
            JSON.parse(publicKeyEntryJSON) :
            publicKeyEntryJSON
    )

    return {
        ...publicKeyEntry,
        spki: (
            typeof publicKeyEntry.spki === 'string' ?
                fromBase64String(publicKeyEntry.spki) :
                publicKeyEntry.spki
        ),
        raw: (
            typeof publicKeyEntry.raw === 'string' ?
                fromBase64String(publicKeyEntry.raw) :
                publicKeyEntry.raw
        ),
    }
}

function fromBase64String (val:string):Uint8Array {
    return sodium.from_base64(val, sodium.base64_variants.ORIGINAL)
}

function toBase64String (val:Uint8Array):string {
    return sodium.to_base64(val, sodium.base64_variants.ORIGINAL)
}

function packPublicKeyJSON (
    publicKeyEntry:PassKeyPublicKey,
    stringify = false
) {
    publicKeyEntry = {
        ...publicKeyEntry,
        spki: (
            typeof publicKeyEntry.spki !== 'string' ?
                toBase64String(publicKeyEntry.spki) :
                publicKeyEntry.spki
        ),
        raw: (
            typeof publicKeyEntry.raw !== 'string' ?
                toBase64String(publicKeyEntry.raw) :
                publicKeyEntry.raw
        ),
    }

    return (stringify ? JSON.stringify(publicKeyEntry) : publicKeyEntry)
}

function regDefaults ({
    credentialType = 'publicKey',
    authenticatorSelection: {
        authenticatorAttachment = 'platform',
        userVerification = 'required',
        residentKey = 'required',
        requireResidentKey = true,

        ...otherAuthenticatorSelctionProps
    } = {},
    relyingPartyID = document.location.hostname,
    relyingPartyName = 'wacg',
    attestation = 'none',
    challenge = sodium.randombytes_buf(20),
    excludeCredentials = [
        // { type: "public-key", id: ..., }
    ],
    user: {
        name: userName = 'wacg-user',
        displayName: userDisplayName = userName,
        id: userID = sodium.randombytes_buf(5),
    } = {},
    publicKeyCredentialParams = (
        publicKeyAlgorithms.map(entry => ({
            type: 'public-key',
            alg: entry.COSEID,
        }))
    ),
    signal: cancelRegistrationSignal,
    ...otherPubKeyOptions
} = {}) {
    const defaults = {
        [credentialType]: {
            authenticatorSelection: {
                authenticatorAttachment,
                userVerification,
                residentKey,
                requireResidentKey,
                ...otherAuthenticatorSelctionProps
            },

            attestation,

            rp: {
                id: relyingPartyID,
                name: relyingPartyName,
            },

            user: {
                name: userName,
                displayName: userDisplayName,
                id: userID,
            },

            challenge,

            excludeCredentials,

            pubKeyCredParams: publicKeyCredentialParams,

            ...otherPubKeyOptions,
        },

        ...(cancelRegistrationSignal != null ? { signal: cancelRegistrationSignal, } : null),
    }

    // internal meta-data only
    Object.defineProperty(
        defaults,
        credentialTypeKey,
        {
            enumerable: false,
            writable: false,
            configurable: false,
            value: credentialType,
        }
    )

    return defaults
}
