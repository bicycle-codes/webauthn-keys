import { del, get, set } from 'idb-keyval'
import libsodium from 'libsodium-wrappers'
import { ASN1, type ASN1Data } from '@bicycle-codes/asn1'
import { PUBLIC_KEY_ALGORITHMS } from './constants'
import type { PassKeyPublicKey, Identity, JSONValue } from './types'
// import Debug from '@substrate-system/debug'
// const debug = Debug()

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

export function normalizeCredentialsList (
    credList:(any & { id:string|Uint8Array })[]
):PublicKeyCredentialDescriptor[] {
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

    return []
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

function findValue (node:ASN1Data):Uint8Array|null {
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
export function parseAuthenticatorData (authData:Uint8Array):{
    rpIdHash:Uint8Array;
    flags:number;
    userPresence:boolean;
    userVerification:boolean;
    signCount?:number;
} {
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

export function fromUTF8String (val:string):Uint8Array {
    return sodium.from_string(val)
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

export async function localIdentities ():Promise<Record<string, Identity>|null> {
    const ids = await loadLocalIdentities()
    return ids
}

/**
 * Add a single new identity to local indexedDB.
 */
export async function pushLocalIdentity (localId:string, id:Identity):Promise<void> {
    let existingIds = await localIdentities()
    if (!existingIds) existingIds = {}
    existingIds[localId] = id
    storeLocalIdentities(existingIds)
}

/**
 * Set the local storage identities
 */
export async function storeLocalIdentities (
    _identities:Record<string, Identity>
):Promise<void> {
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

    if (Object.keys(identities).length > 0) {
        return await set('local-identities', identities)
    } else {
        return await del('local-identities')
    }
}

async function loadLocalIdentities ():Promise<Record<string, Identity>|null> {
    const localIds = await get('local-identities') || {}
    if (!Object.keys(localIds).length) return null

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

export function isByteArray (val:unknown):boolean {
    return (val instanceof Uint8Array && val.buffer instanceof ArrayBuffer)
}

export function asBufferOrString (
    data:Uint8Array|ArrayBuffer|string|JSONValue
):Uint8Array|string {
    if (data instanceof ArrayBuffer) {
        return new Uint8Array(data)
    }

    if (isByteArray(data)) {
        return (data as Uint8Array)
    }

    if (typeof data === 'object') {
        // assume JSON serializable
        return JSON.stringify(data)
    }

    // data must be a string
    return String(data)
}

export type NumericArray = number[] | Uint8Array | Int8Array | Uint16Array
    | Int16Array | Uint32Array | Int32Array | Float32Array | Float64Array;

/**
 * Sets all values in the given array to zero and returns it.
 *
 * The fact that it sets bytes to zero can be relied on.
 *
 * There is no guarantee that this function makes data disappear from memory,
 * as runtime implementation can, for example, have copying garbage collector
 * that will make copies of sensitive data before we wipe it. Or that an
 * operating system will write our data to swap or sleep image. Another thing
 * is that an optimizing compiler can remove calls to this function or make it
 * no-op. There's nothing we can do with it, so we just do our best and hope
 * that everything will be okay and good will triumph over evil.
 *
 * @see {@link https://github.com/StableLib/stablelib/blob/master/packages/wipe/wipe.ts stablelib}
 */
export function wipe (array:NumericArray):NumericArray {
    for (let i = 0; i < array.length; i++) {
        array[i] = 0
    }
    return array
}

// NOTE: these are ordered by "preference" for key
// generation by WebAuthn create()
const publicKeyAlgorithms = [
    // Ed25519 / EdDSA
    // https://oid-rep.orange-labs.fr/get/1.3.101.112
    {
        name: 'Ed25519',
        COSEID: -8,
        // note: Ed25519 is in draft, but not yet supported
        // by subtle-crypto
        //    https://wicg.github.io/webcrypto-secure-curves/
        //    https://www.rfc-editor.org/rfc/rfc8410
        //    https://caniuse.com/mdn-api_subtlecrypto_importkey_ed25519
        cipherOpts: {
            name: 'Ed25519',
            hash: { name: 'SHA-512', },
        },
    },

    // ES256 / ECDSA (P-256)
    // https://oid-rep.orange-labs.fr/get/1.2.840.10045.2.1
    {
        name: 'ES256',
        COSEID: -7,
        cipherOpts: {
            name: 'ECDSA',
            namedCurve: 'P-256',
            hash: { name: 'SHA-256', },
        },
    },

    // RSASSA-PSS
    // https://oid-rep.orange-labs.fr/get/1.2.840.113549.1.1.10
    {
        name: 'RSASSA-PSS',
        COSEID: -37,
        cipherOpts: {
            name: 'RSA-PSS',
            hash: { name: 'SHA-256', },
        },
    },

    // RS256 / RSASSA-PKCS1-v1_5
    // https://oid-rep.orange-labs.fr/get/1.2.840.113549.1.1.1
    {
        name: 'RS256',
        COSEID: -257,
        cipherOpts: {
            name: 'RSASSA-PKCS1-v1_5',
            hash: { name: 'SHA-256', },
        },
    },
] as const

export type COSE_NAME = (typeof publicKeyAlgorithms)[number]['name']

export const publicKeyAlgorithmsLookup = Object.fromEntries(
    publicKeyAlgorithms.flatMap(entry => [
        // by name
        [entry.name, entry,],

        // by COSEID
        [entry.COSEID, entry,],
    ])
)

export async function verifySignatureSubtle (
    publicKeySPKI:Uint8Array|string,
    algoCOSE:COSEAlgorithmIdentifier,
    signature:BufferSource,
    data:BufferSource
) {
    if (
        isPublicKeyAlgorithm('ES256', algoCOSE) ||
        isPublicKeyAlgorithm('RSASSA-PSS', algoCOSE) ||
        isPublicKeyAlgorithm('RS256', algoCOSE)
    ) {
        try {
            const pubKeySubtle = await crypto.subtle.importKey(
                'spki',  // Simple Public Key Infrastructure rfc2692
                typeof publicKeySPKI === 'string' ?
                    fromBase64String(publicKeySPKI) :
                    publicKeySPKI,
                publicKeyAlgorithmsLookup[algoCOSE].cipherOpts,
                false,  // extractable
                ['verify']
            )

            return await crypto.subtle.verify(
                publicKeyAlgorithmsLookup[algoCOSE].cipherOpts,
                pubKeySubtle,
                signature,
                data
            )
        } catch (err) {
            console.log(err)
            return false
        }
    }
    throw new Error('Unrecognized signature for subtle-crypto verification')
}

export function verifySignatureSodium (
    publicKeyRaw:Uint8Array,
    algoCOSE:COSEAlgorithmIdentifier,
    signature:Uint8Array,
    data:Uint8Array
) {
    if (isPublicKeyAlgorithm('Ed25519', algoCOSE)) {
        try {
            return sodium.crypto_sign_verify_detached(signature, data, publicKeyRaw)
        } catch (err) {
            console.log(err)
            return false
        }
    }
    throw new Error('Unrecognized signature for sodium verification')
}

function isPublicKeyAlgorithm (
    algoName:COSE_NAME,
    COSEID:COSEAlgorithmIdentifier
) {
    return (publicKeyAlgorithmsLookup[algoName] ===
        publicKeyAlgorithmsLookup[COSEID])
}

export async function computeVerificationData (
    authDataRaw:ArrayBuffer,
    clientDataRaw:ArrayBuffer
):Promise<Uint8Array> {
    const clientDataHash = await computeSHA256Hash(clientDataRaw)
    const data = new Uint8Array(
        authDataRaw.byteLength + clientDataHash.byteLength
    )
    data.set(new Uint8Array(authDataRaw), 0)
    data.set(clientDataHash, authDataRaw.byteLength)

    return data
}

async function computeSHA256Hash (val:ArrayBuffer) {
    return new Uint8Array(
        await window.crypto.subtle.digest(
            'SHA-256',
            new Uint8Array(val)
        )
    )
}
