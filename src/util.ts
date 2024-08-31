import libsodium from 'libsodium-wrappers'
import ASN1 from '@yoursunny/asn1'
import { PUBLIC_KEY_ALGORITHMS } from './constants'
import type { PassKeyPublicKey } from './types'

await libsodium.ready
const sodium = libsodium

export const credentialTypeKey = Symbol('credential-type')
export const resetAbortReason = Symbol('reset-abort')

export async function supportsWebAuthn () {
    return (
        typeof navigator !== 'undefined' &&
        typeof navigator.credentials !== 'undefined' &&
        typeof navigator.credentials.create !== 'undefined' &&
        typeof navigator.credentials.get !== 'undefined' &&
        typeof PublicKeyCredential !== 'undefined' &&
        typeof PublicKeyCredential
            .isUserVerifyingPlatformAuthenticatorAvailable !== 'undefined' &&
        (await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable())
    )
}

export function normalizeCredentialsList (credList) {
    if (Array.isArray(credList)) {
        return credList.map(entry => ({
            ...entry,
            id: (
                typeof entry.id === 'string' ?
                    fromBase64String(entry.id) :
                    entry.id
            ),
        }))
    }
}

export function fromBase64String (val:string):Uint8Array {
    return sodium.from_base64(val, sodium.base64_variants.ORIGINAL)
}

export function toBase64String (val:Uint8Array):string {
    return sodium.to_base64(val, sodium.base64_variants.ORIGINAL)
}

export function toUTF8String (val:Uint8Array):string {
    return sodium.to_string(val)
}

// Adapted from: https://www.npmjs.com/package/@yoursunny/webcrypto-ed25519
export function parsePublicKeySPKI (publicKeySPKI) {
    const der = ASN1.parseVerbose(new Uint8Array(publicKeySPKI))
    return {
        algo: sodium.to_hex(findValue(der.children![0])!),
        raw: findValue(der.children![1]),
    }
}

function findValue (node:ASN1.ElementBuffer):Uint8Array|null {
    if (node.value && node.value instanceof Uint8Array) {
        return node.value
    } else if (node.children) {
        for (const child of node.children) {
            const res = findValue(child)
            if (res !== null) {
                return res
            }
        }
    }

    return null
}

/**
 * @see {@link https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Authenticator_data data}
 * 32 bytes: rpIdHash
 *  1 byte: flags
 *
 * Bit 0, User Presence (UP)
 * Bit 2, User Verification (UV)
 * Bit 3, Backup Eligibility (BE)
 * Bit 4, Backup State (BS)
 * Bit 6, Attested Credential Data (AT)
 * Bit 7, Extension Data (ED)
 * 4 bytes: signCount (0 means disabled)
 */
export function parseAuthenticatorData (authData:Uint8Array) {
    return {
        rpIdHash: authData.slice(0, 32),
        flags: authData[32],
        userPresence: ((authData[32] & 1) === 1),
        userVerification: ((authData[32] & 4) === 4),
        signCount: byteArrayTo32Int(authData.slice(33, 37)),
    }
}

function byteArrayTo32Int (byteArray:Uint8Array):number {
    // not enough bytes for 32-bit integer?
    if (byteArray.byteLength < 4) {
        // zero-pad byte(s) at start of array
        const tmp = new Uint8Array(4)
        tmp.set(byteArray, 4 - byteArray.byteLength)
        byteArray = tmp
    }

    return new DataView(byteArray.buffer).getInt32(0)
}

export async function checkRPID (rpIDHash, origRPID) {
    const originHash = await computeSHA256Hash(fromUTF8String(origRPID))

    return (
        rpIDHash.length > 0 &&
        rpIDHash.byteLength === originHash.byteLength &&
        rpIDHash.toString() === originHash.toString()
    )
}

function fromUTF8String (val:string):Uint8Array {
    return sodium.from_string(val)
}

async function computeSHA256Hash (val) {
    return new Uint8Array(
        await window.crypto.subtle.digest(
            'SHA-256',
            new Uint8Array(val)
        )
    )
}

export function getPublicKeyOpts (opts:Partial<{
    username:string;
    usernameDisplay:string;
    userID:Uint8Array;
    relyingPartyID:string;
    relyingPartyName:string;
}> = {}):PublicKeyCredentialCreationOptions {
    const { username, usernameDisplay, userID } = opts

    const publicKeyCredentialParams = (
        PUBLIC_KEY_ALGORITHMS.map(params => ({
            type: 'public-key' as const,
            alg: params.COSEID,
        }))
    )

    return {
        attestation: 'none',
        authenticatorSelection: {
            authenticatorAttachment: 'platform',
            userVerification: 'required',
            residentKey: 'required',
            requireResidentKey: true
        },
        challenge: sodium.randombytes_buf(20),
        excludeCredentials: [
            // { type: "public-key", id: ..., }
        ],
        pubKeyCredParams: publicKeyCredentialParams,
        rp: {
            id: opts.relyingPartyID || document.location.hostname,
            name: opts.relyingPartyName || 'wacg'
        },
        user: {
            name: username || 'anonymous',
            displayName: usernameDisplay || username || 'anonymous',
            id: userID || sodium.randombytes_buf(5)
        }
    }
}

// export function regDefaults ({
//     credentialType = 'publicKey',
//     authenticatorSelection: {
//         authenticatorAttachment = 'platform',
//         userVerification = 'required',
//         residentKey = 'required',
//         requireResidentKey = true,

//         ...otherAuthenticatorSelctionProps
//     } = {},
//     relyingPartyID = document.location.hostname,
//     relyingPartyName = 'wacg',
//     attestation = 'none',
//     challenge = sodium.randombytes_buf(20),
//     excludeCredentials = [
//         // { type: "public-key", id: ..., }
//     ],
//     user: {
//         name: userName = 'wacg-user',
//         displayName: userDisplayName = userName,
//         id: userID = sodium.randombytes_buf(5),
//     } = {},
//     publicKeyCredentialParams = (
//         PUBLIC_KEY_ALGORITHMS.map(entry => ({
//             type: 'public-key',
//             alg: entry.COSEID,
//         }))
//     ),
//     signal: cancelRegistrationSignal = null,
//     ...otherPubKeyOptions
// }:Partial<PublicKeyCredentialCreationOptions> = {}):CredentialCreationOptions {
//     const defaults = {
//         relyingPartyID,

//         [credentialType]: {
//             authenticatorSelection: {
//                 authenticatorAttachment,
//                 userVerification,
//                 residentKey,
//                 requireResidentKey,
//                 ...otherAuthenticatorSelctionProps
//             },

//             attestation,

//             rp: {
//                 id: relyingPartyID,
//                 name: relyingPartyName,
//             },

//             user: {
//                 name: userName,
//                 displayName: userDisplayName,
//                 id: userID,
//             },

//             challenge,

//             excludeCredentials,

//             pubKeyCredParams: publicKeyCredentialParams,

//             ...otherPubKeyOptions,
//         },

//         ...(cancelRegistrationSignal !== null ?
//             { signal: cancelRegistrationSignal } :
//             null),
//     }

//     // internal meta-data only
//     Object.defineProperty(
//         defaults,
//         credentialTypeKey,
//         {
//             enumerable: false,
//             writable: false,
//             configurable: false,
//             value: credentialType,
//         }
//     )

//     return defaults
// }

export function buildPasskeyEntry (passkey) {
    return {
        ...passkey,
        hash: computePasskeyEntryHash(passkey),
    }
}

function computePasskeyEntryHash (passkeyEntry) {
    const { hash: _, ...passkey } = passkeyEntry

    return toBase64String(sodium.crypto_hash(JSON.stringify({
        ...passkey,
        publicKey: packPublicKeyJSON(passkey.publicKey),
    })))
}

export function unpackPublicKeyJSON (publicKeyEntryJSON:PassKeyPublicKey) {
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

export function packPublicKeyJSON (
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
