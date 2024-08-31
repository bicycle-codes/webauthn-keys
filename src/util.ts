import store from '@lo-fi/client-storage/idb'
import libsodium from 'libsodium-wrappers'
import ASN1 from '@yoursunny/asn1'
import { PUBLIC_KEY_ALGORITHMS } from './constants'
import type { PassKeyPublicKey, Identity } from './types'
import Debug from '@bicycle-codes/debug'
const debug = Debug()

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
export function parsePublicKeySPKI (publicKeySPKI:Uint8Array):{
    algo:string;
    raw:Uint8Array
} {
    const der = ASN1.parseVerbose(new Uint8Array(publicKeySPKI))
    return {
        algo: sodium.to_hex(findValue(der.children![0])!),
        raw: findValue(der.children![1])!,
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

// export function buildPasskeyEntry (passkey:Passkey):Passkey & { hash:string } {
export function buildPasskeyEntry (passkey:{
    seq:number;
    credentialID:string;
    publicKey:{
        algoCOSE:COSEAlgorithmIdentifier;
        algoOID:string;
        spki:Uint8Array;
        raw:Uint8Array;
    }
}) {
    return {
        ...passkey,
        publicKey: packPublicKeyJSON(passkey.publicKey) as PassKeyPublicKey,
        hash: computePasskeyEntryHash(passkey),
    }
}

function computePasskeyEntryHash (passkeyEntry) {
    const { hash: _, ...passkey } = passkeyEntry

    /**
     * @TODO
     * use json-canon here
     */
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
    publicKey:{
        algoCOSE:COSEAlgorithmIdentifier;
        algoOID:string;
        spki:Uint8Array|string;
        raw:Uint8Array|string;
    },
    stringify = false
):string|PassKeyPublicKey {
    const _publicKey = {
        ...publicKey,
        spki: (
            typeof publicKey.spki !== 'string' ?
                toBase64String(publicKey.spki) :
                publicKey.spki
        ),
        raw: (
            typeof publicKey.raw !== 'string' ?
                toBase64String(publicKey.raw) :
                publicKey.raw
        ),
    }

    return (stringify ? JSON.stringify(_publicKey) : _publicKey)
}

export async function localIdentities ():Promise<Record<string, Identity>> {
    const ids = await loadLocalIdentities()
    return ids
}

/**
 * Add a single new identity to local storage.
 */
export async function pushLocalIdentity (localId:string, id:Identity) {
    const existingIds = await localIdentities()
    existingIds[localId] = id
    storeLocalIdentities(existingIds)
}

/**
 * Set the local storage identities
 */
export async function storeLocalIdentities (_identities:Record<string, Identity>) {
    const identities = Object.fromEntries(
        Object.entries(_identities)
            .map(([localID, entry]) => ([
                localID,
                {
                    ...entry,
                    passkeys: entry.passkeys.map(passkey => ({
                        ...passkey,
                        publicKey: packPublicKeyJSON(passkey.publicKey),
                    }))
                },
            ]))
    )

    debug('identities...', identities)

    if (Object.keys(identities).length > 0) {
        await store.set('local-identities', identities)
    } else {
        await store.remove('local-identities')
    }
}

async function loadLocalIdentities ():Promise<Record<string, Identity>> {
    const localIds = await store.get('local-identities') || {}
    debug('local ids', localIds)

    return (
        Object.fromEntries(
            Object.entries<Identity>(localIds)
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

// function computePasskeyEntryHash (passkeyEntry:Passkey) {
//     const { hash: _, ...passkey } = passkeyEntry
//     return toBase64String(sodium.crypto_hash(JSON.stringify({
//         ...passkey,
//         publicKey: packPublicKeyJSON(passkey.publicKey),
//     })))
// }
