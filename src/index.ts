import libsodium from 'libsodium-wrappers'
import {
    supportsWebAuthn,
    toBase64String,
    normalizeCredentialsList,
    toUTF8String,
    parsePublicKeySPKI,
    parseAuthenticatorData,
    checkRPID,
    buildPasskeyEntry,
    credentialTypeKey,
    resetAbortReason,
    localIdentities,
    storeLocalIdentities,
    pushLocalIdentity,
    asBufferOrString,
    fromBase64String,
    publicKeyAlgorithmsLookup,
    verifySignatureSubtle,
    verifySignatureSodium,
    computeVerificationData,
} from './util'
import { ASN1Parser as ASN1 } from '@bicycle-codes/asn1'
import type {
    Identity,
    RegistrationResult,
    LockKey,
    JSONValue,
    PassKeyPublicKey,
} from './types'
import { decode as cborDecode } from 'cborg'
import { PUBLIC_KEY_ALGORITHMS } from './constants'
import { createDebug } from '@substrate-system/debug'
const debug = createDebug()

export {
    localIdentities as listLocalIdentities,
    storeLocalIdentities,
    pushLocalIdentity,
    toBase64String,
    fromBase64String,
    supportsWebAuthn
}

await libsodium.ready
const sodium = libsodium

// const externalSignalCache = new WeakMap()
const IV_BYTE_LENGTH = sodium.crypto_sign_SEEDBYTES
const CURRENT_LOCK_KEY_FORMAT_VERSION = 1

/**
 * Create a new keypair.
 * This registers a new identity
 */
export async function create (
    _opts:Partial<{
        excludeCredentials: string[];
        username:string
        displayName:string
        relyingPartyID:string
        relyingPartyName:string
    }> = {
        username: 'local-user',
        displayName: 'Local User',
        relyingPartyID: document.location.hostname,
        relyingPartyName: 'demo'
    }
):Promise<{ localID:string, record:Identity, keys:LockKey }> {
    const lockKey = deriveLockKey()
    const abortToken = new AbortController()
    const opts = Object.assign({
        username: 'local-user',
        displayName: 'Local User',
        relyingPartyID: document.location.hostname,
        relyingPartyName: 'demo'
    }, _opts)
    const { username, displayName, relyingPartyID, relyingPartyName } = opts

    let result:{ localID:string, record:Identity, keys:LockKey }
    try {
        const localID:string = toBase64String(generateEntropy(15))
        const lastSeq:number = 0

        /**
         * @NOTE
         * Encode the userHandle field of the passkey with the
         * first 32 bytes of the keypair IV, and then 2 bytes
         * to encode (big-endian) a passkey sequence value; this
         * additional value allows multiple passkeys (up to 65,535 of
         * them) registered on the same authenticator, sharing the same
         * keypair IV in its userHandle.
         */
        const userHandle = new Uint8Array(lockKey.iv.byteLength + 2)
        const seqBytes = new DataView(new ArrayBuffer(2))
        seqBytes.setInt16(0, lastSeq, /* littleEndian= */false)
        userHandle.set(lockKey.iv, 0)
        userHandle.set(new Uint8Array(seqBytes.buffer), lockKey.iv.byteLength)

        const opts = regDefaults({
            signal: abortToken.signal,
            relyingPartyID,
            relyingPartyName,
            user: {
                id: userHandle,
                name: username,
                displayName
            }
        })

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

        result = {
            record: {
                username,
                displayName,
                lastSeq,
                passkeys: [
                    buildPasskeyEntry({
                        seq: lastSeq,
                        credentialID: registrationResult.response.credentialID,
                        publicKey: registrationResult.response.publicKey,
                    }),
                ],
            },
            localID,
            keys: lockKey,
        }
    } catch (err) {
        throw new Error('Identity/Passkey registration failed', { cause: err })
    }

    return result
}

/**
 * Delete an account from storage (indexedDB).
 *
 * @param {string[]} localIDs The public IDs to remove
 * @returns {Promise<void>}
 */
export async function removeLocalAccounts (localIDs:string[]):Promise<void> {
    const locals = await localIdentities()
    if (!locals) return
    const newids = Object.keys(locals).reduce((acc, k) => {
        if (localIDs.indexOf(k) > -1) return acc  // filter
        acc[k] = locals[k]
        return acc
    }, {})
    await storeLocalIdentities(newids)
}

export function deriveLockKey (iv = generateEntropy(IV_BYTE_LENGTH)):LockKey {
    debug('deriving the key', iv)
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

        const regOpt:'public-key' = regOptions[credentialTypeKey]  // 'public-key'

        regOptions[regOpt].excludeCredentials = (
            // ensure credential IDs are binary (not base64 string)
            normalizeCredentialsList(
                regOptions[regOpt].excludeCredentials
            )
        )

        const regResult = (await navigator.credentials
            .create(regOptions)) as PublicKeyCredential

        const response = regResult!.response as AuthenticatorAttestationResponse
        const regClientDataRaw = new Uint8Array(response.clientDataJSON)

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

                cborDecode(
                    new Uint8Array(response.attestationObject)
                ).authData
        )

        const regAuthData = parseAuthenticatorData(
            regAuthDataRaw
        ) as ReturnType<typeof parseAuthenticatorData>

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
        }  // else, was aborted
    }

    return res!
}

/**
 * Get the keys from a successful login resposne.
 */
export function getKeys (opts:{
    response:AuthenticatorAssertionResponse
}):LockKey {
    debug('in here', opts.response)
    debug('in here, the user handle', opts.response.userHandle)
    const key = extractLockKey({
        userID: new Uint8Array(opts.response.userHandle!)
    })

    return key
}

/**
 * Get a base64 string of the given public key.
 *
 * @returns {string} A base64 string of the given public key.
 */
export function stringify (keys:LockKey):string {
    return toBase64String(keys.publicKey)
    // => 'welOX9O96R6WH0S8cqqwMlPAJ3VwMgAZEnc1wa1MN70='
}

/**
 * Auth
 * @param {string} localId The ID we are authenticating
 * @param {Partial<CredentialRequestOptions> & {
    * relyingPartyID?:string
 * }} opts Some config
 * @param {{ verify:boolean }} options More config
 * @returns {Promise<{ request, response }>}
 */
export async function auth (
    localId:string,
    opts:Partial<CredentialRequestOptions> & Partial<{
        relyingPartyID:string
    }> = {},
    { verify }:{ verify?:boolean } = {}
):Promise<{ request, response }> {
    const ids = await localIdentities()
    if (!ids) throw new Error('not ids')

    const relyingPartyID = opts.relyingPartyID || document.location.hostname
    const identityRecord = ids[localId]
    debug('authenticating...', identityRecord)
    const authOptions = authDefaults({
        relyingPartyID,
        mediation: 'optional',
        // signal: abortToken.signal,
    }, {
        allowCredentials: (
            identityRecord.passkeys.map(({ credentialID, }) => ({
                type: 'public-key',
                id: fromBase64String(credentialID),
            }))
        ),
    })

    authOptions.publicKey!.allowCredentials = normalizeCredentialsList(
        authOptions.publicKey!.allowCredentials!
    )

    const authRes = (await navigator.credentials.get(authOptions)) as PublicKeyCredential|null
    if (!authRes) throw new Error('not credentials.get()')

    const authClientDataRaw = new Uint8Array(authRes.response.clientDataJSON)
    const authClientData = JSON.parse(toUTF8String(authClientDataRaw))
    if (authClientData.type !== 'webauthn.get') {
        throw new Error('Invalid auth response')
    }
    // debug('aaaaaa', credentialTypeKey)
    debug('aaaaaaa', authOptions)
    // debug('cccccc', authOptions[credentialTypeKey])
    const publicKeyParams = authOptions.publicKey
    if (!publicKeyParams) throw new Error('not public key params')
    const expectedChallenge = sodium.to_base64(
        toUint8Array(publicKeyParams.challenge),
        sodium.base64_variants.URLSAFE_NO_PADDING
    )
    if (authClientData.challenge !== expectedChallenge) {
        throw new Error('Challenge not accepted')
    }
    const _response = authRes.response as AuthenticatorAssertionResponse
    const authDataRaw = new Uint8Array(
        _response.authenticatorData
    )
    const authData = parseAuthenticatorData(authDataRaw)
    if (!checkRPID(authData.rpIdHash, relyingPartyID)) {
        throw new Error('Unexpected relying-party ID')
    }
    // sign-count not supported by this authenticator?
    if (authData.signCount === 0) {
        delete authData.signCount
    }

    const signatureRaw = new Uint8Array(_response.signature)

    if (verify) {
        const passkey = identityRecord.passkeys.find(passkey => {
            // see https://github.com/mylofi/webauthn-local-client/blob/d0a759e463de7fc2b4ae84799fc5122d3749279f/src/walc.js#L353
            // credentialID: toBase64String(new Uint8Array(authResult.rawId)),
            const id = toBase64String(new Uint8Array(authRes.rawId))
            return (passkey.credentialID === id)
        })

        const publicKey = passkey?.publicKey as PassKeyPublicKey
        const verified = (
            publicKey ?
                (await verifyAuthResponse(
                    _response,
                    publicKey
                )) :
                false
        )

        if (!verified) {
            throw new Error('Auth verification failed')
        }
    }

    debug('the handle in `auth`', _response.userHandle)

    return {
        request: {
            credentialType: authRes.type,
            mediation: authOptions.mediation,
            ...authOptions[authOptions[credentialTypeKey]],
            ...Object.fromEntries(
                Object.entries(authClientData).filter(([k, _v]) => {
                    return ['origin', 'crossOrigin'].includes(k)
                })
            )
        },
        response: {
            ..._response,
            // need to put `userHandle` specifically, I don't know why
            userHandle: _response.userHandle,
            credentialID: toBase64String(new Uint8Array(authRes.rawId)),
            signature: signatureRaw,
            ...(Object.fromEntries(
                Object.entries(authData).filter(([key]) => (
                    ['flags', 'signCount', 'userPresence',
                        'userVerification'].includes(key)
                ))
            )),
            ...(_response.userHandle != null ?
                { userID: new Uint8Array(_response.userHandle) } :
                null
            ),
        }
    }
}

/**
 * If called with { parseJSON: false }, will return
 * a string.
 *
 * If called with { outputFormat: 'raw' }, will return
 * a Uint8Array.
 */
export function decrypt (
    data:string|Uint8Array,
    lockKey:LockKey,
    { outputFormat }:{
        outputFormat?:'raw'
    }
):Uint8Array
export function decrypt (
    data:string|Uint8Array,
    lockKey:LockKey,
    { outputFormat, parseJSON }:{
        outputFormat?:'utf8',
        parseJSON:false
    }
):string
export function decrypt (
    data:string|Uint8Array,
    lockKey:LockKey,
    { outputFormat, parseJSON }:{
        outputFormat?:'utf8',
        parseJSON?:true
    }
):JSONValue
export function decrypt (
    data:string|Uint8Array,
    lockKey:LockKey,
    opts:{ outputFormat?:'utf8'|'raw', parseJSON?:boolean } = {
        outputFormat: 'utf8',
        parseJSON: true
    }
):string|Uint8Array|JSONValue {
    const outputFormat = opts.outputFormat || 'utf8'
    const parseJSON = opts.parseJSON ?? true

    const dataBuffer = sodium.crypto_box_seal_open(
        typeof data === 'string' ? fromBase64String(data) : data,
        lockKey.encPK,
        lockKey.encSK
    )

    if (outputFormat === 'utf8') {
        const decodedData = toUTF8String(dataBuffer)
        return (parseJSON ? JSON.parse(decodedData) : decodedData)
    }

    return dataBuffer
}

export async function verify (
    data:string|Uint8Array,
    sig:string|Uint8Array,
    keys:{ publicKey:Uint8Array|string }
):Promise<boolean> {
    await libsodium.ready
    const sodium = libsodium

    try {
        const pubKey = typeof keys.publicKey === 'string' ?
            fromBase64String(keys.publicKey) :
            keys.publicKey

        const isOk = sodium.crypto_sign_verify_detached(
            typeof sig === 'string' ? fromBase64String(sig) : sig,
            asBufferOrString(data),
            pubKey
        )

        return isOk
    } catch (_err) {
        return false
    }
}

export async function signData (
    data:string|Uint8Array,
    key:LockKey
):Promise<string>

export async function signData (data:string|Uint8Array, key:LockKey, opts:{
    outputFormat:'raw'
}):Promise<Uint8Array>

/**
 * Sign the given data.
 * @param data The data to sign.
 * @param key The keys to use
 * @param opts Can specify 'raw' as `outputFormat`, which will return
 * a `Uint8Array` instead of a string.
 * @returns {string|Uint8Array} String or binary, depending on `opts`
 */
export async function signData (
    data:string|Uint8Array,
    key:LockKey,
    opts?:{
        outputFormat?:'base64'|'raw'
    }
):Promise<string|Uint8Array> {
    await libsodium.ready
    const sodium = libsodium

    const outputFormat = opts?.outputFormat || 'base64'

    const sig = sodium.crypto_sign_detached(
        data,
        key.privateKey
    )

    return outputFormat === 'base64' ? toBase64String(sig) : sig
}

export function encrypt (data:JSONValue, lockKey):string
export function encrypt (data:JSONValue, lockKey, { outputFormat }:{
    outputFormat:'base64'
}):string
export function encrypt (data:JSONValue, lockKey, { outputFormat }:{
    outputFormat:'raw'
}):Uint8Array
export function encrypt (
    data:JSONValue,
    lockKey:LockKey,
    opts:{
        outputFormat:'base64'|'raw';
    } = { outputFormat: 'base64' }
// return type depends on the given output format
):string|Uint8Array {
    const { outputFormat } = opts

    if (data == null) {
        throw new Error('Non-empty data required.')
    }

    try {
        const dataBuffer = asBufferOrString(data)
        const encData = sodium.crypto_box_seal(dataBuffer, lockKey.encPK)

        const output = (outputFormat.toLowerCase() === 'base64') ?
            toBase64String(encData) :
            encData
        return output
    } catch (err) {
        throw new Error('Data encryption failed.', { cause: err })
    }
}

// interface PublicKeyCredentialRequestOptions {
//     allowCredentials?: PublicKeyCredentialDescriptor[];
//     challenge: BufferSource;
//     extensions?: AuthenticationExtensionsClientInputs;
//     rpId?: string;
//     timeout?: number;
//     userVerification?: UserVerificationRequirement;
// }

// interface CredentialRequestOptions {
//     mediation?: CredentialMediationRequirement;
//     publicKey?: PublicKeyCredentialRequestOptions;
//     signal?: AbortSignal;
// }

export function authDefaults (
    opts:Partial<CredentialRequestOptions> & Partial<{
        relyingPartyID:string;
    }> = {},
    keyOpts:Partial<PublicKeyCredentialRequestOptions> = {}
):CredentialRequestOptions {
    const allowCredentials = keyOpts.allowCredentials || [
        // { type: "public-key", id: ..., }
    ]
    const defaults:CredentialRequestOptions = {
        mediation: opts.mediation || 'conditional',
        publicKey: {
            rpId: opts.relyingPartyID || location.hostname,
            userVerification: keyOpts.userVerification || 'required',
            allowCredentials,
            challenge: keyOpts.challenge ?
                toUint8Array(keyOpts.challenge) :
                sodium.randombytes_buf(20),
            ...keyOpts,
        },

        ...opts
    }

    return defaults
}

function toUint8Array (bufferSource:BufferSource):Uint8Array {
    if (bufferSource instanceof ArrayBuffer) {
        return new Uint8Array(bufferSource)
    } else if (bufferSource instanceof Uint8Array) {
        return bufferSource
    } else if (bufferSource instanceof DataView) {
        return new Uint8Array(
            bufferSource.buffer,
            bufferSource.byteOffset,
            bufferSource.byteLength
        )
    } else {
        throw new Error('Unsupported BufferSource type')
    }
}

function extractLockKey ({ userID }:{ userID:Uint8Array }) {
    debug('extracting...', userID)
    const lockKey = deriveLockKey(userID.subarray(0, IV_BYTE_LENGTH))
    return lockKey
}

async function verifyAuthResponse (
    /* response= */{
        signature,
        raw: {
            clientDataJSON: clientDataRaw,
            authenticatorData: authDataRaw,
        },
    }:Partial<{ signature:ArrayBuffer, raw }> = {},
    {
        // publicKey
        algoCOSE: publicKeyAlgoCOSE,
        spki: publicKeySPKI,
        raw: publicKeyRaw,
    }:Partial<{
        algoCOSE:COSEAlgorithmIdentifier,
        spki:string|Uint8Array,
        raw:Uint8Array|string
    }> = {}
) {
    if (!publicKeyAlgoCOSE) throw new Error('not algoCOSE')
    try {
        // all necessary inputs?
        if (
            signature && clientDataRaw && authDataRaw && publicKeySPKI &&
            publicKeyRaw && Number.isInteger(publicKeyAlgoCOSE)
        ) {
            const verificationSig = parseSignature(publicKeyAlgoCOSE, signature)
            const verificationData = await computeVerificationData(
                authDataRaw,
                clientDataRaw
            )

            const status = await (
                // Ed25519?
                isPublicKeyAlgorithm('Ed25519', publicKeyAlgoCOSE) ?
                    // verification needs sodium (not subtle-crypto)
                    verifySignatureSodium(
                        typeof publicKeyRaw === 'string' ?
                            fromBase64String(publicKeyRaw) :
                            publicKeyRaw
                        ,
                        publicKeyAlgoCOSE,
                        verificationSig,
                        verificationData
                    ) :

                    (
                        // ECDSA (P-256)?
                        isPublicKeyAlgorithm('ES256', publicKeyAlgoCOSE) ||

                        // RSASSA-PKCS1-v1_5?
                        isPublicKeyAlgorithm('RS256', publicKeyAlgoCOSE) ||

                        // RSASSA-PSS
                        isPublicKeyAlgorithm('RSASSA-PSS', publicKeyAlgoCOSE)
                    ) ?
                        // verification supported by subtle-crypto
                        verifySignatureSubtle(
                            publicKeySPKI,
                            publicKeyAlgoCOSE,
                            verificationSig,
                            verificationData
                        ) :

                        null
            )
            if (status == null) {
                throw new Error('Unrecognized signature, failed validation')
            }
            return status
        } else {
            throw new Error('Auth verification missing required inputs')
        }
    } catch (err) {
        throw new Error('Auth verification failed', { cause: err, })
    }
}

function parseSignature (
    algoCOSE:COSEAlgorithmIdentifier,
    signature:ArrayBuffer
):Uint8Array {
    if (isPublicKeyAlgorithm('ES256', algoCOSE)) {
        // this algorithm's signature comes back ASN.1 encoded, per spec:
        //   https://www.w3.org/TR/webauthn-2/#sctn-signature-attestation-types
        const der = ASN1.parseVerbose(new Uint8Array(signature))
        return new Uint8Array(
            [...der.children[0].value, ...der.children[1].value]
        )
    }

    // also per spec, other signature algorithms SHOULD NOT come back
    // in ASN.1, so for those, we just pass through without any parsing
    return new Uint8Array(signature)
}

function isPublicKeyAlgorithm (algoName, COSEID) {
    return (
        publicKeyAlgorithmsLookup[algoName] === publicKeyAlgorithmsLookup[COSEID]
    )
}

type RegOpts = {
    credentialType:'publicKey';
    authenticatorSelection:Partial<{
        authenticatorAttachment:AuthenticatorAttachment;
        userVerification:'required';
        residentKey:'required',
        requireResidentKey:boolean,
    }>;
    relyingPartyID:string;
    relyingPartyName:string;
    attestation:AttestationConveyancePreference;
    challenge:Uint8Array;
    excludeCredentials:{ type, id }[];
    user:Partial<{
        name:string;
        displayName:string;
        id:Uint8Array;
    }>;
    publicKeyCredentialParams:{ type:'public-key', alg:COSEAlgorithmIdentifier }[];
    signal:AbortSignal;
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
    relyingPartyName = 'wacl',
    attestation = 'none' as AttestationConveyancePreference,
    challenge = sodium.randombytes_buf(20),
    excludeCredentials = [
        // { type: "public-key", id: ..., }
    ],
    user: {
        name: userName = 'wacl-user',
        displayName: userDisplayName = userName,
        id: userID = sodium.randombytes_buf(5),
    } = {},
    publicKeyCredentialParams = (
        PUBLIC_KEY_ALGORITHMS.map(entry => ({
            type: 'public-key',
            alg: entry.COSEID,
        }))
    ),
    signal: cancelRegistrationSignal,
    ...otherPubKeyOptions
}:Partial<RegOpts> = {}):{ publicKey:PublicKeyCredentialCreationOptions } {
    debug('creating another one: ', userID)

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

        ...(cancelRegistrationSignal != null ?
            { signal: cancelRegistrationSignal } :
            null
        ),
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
