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
    pushLocalIdentity,
    asBufferOrString,
    isByteArray
} from './util'
import type {
    Identity,
    RegistrationResult,
    LockKey,
    JSONValue,
    AuthResult
} from './types'
import * as cbor from 'cborg'
const debug = createDebug()

export { localIdentities, storeLocalIdentities, pushLocalIdentity }

await libsodium.ready
const sodium = libsodium

// const externalSignalCache = new WeakMap()
const IV_BYTE_LENGTH = sodium.crypto_sign_SEEDBYTES
const CURRENT_LOCK_KEY_FORMAT_VERSION = 1

/**
 * Create a new keypair.
 * This registers a new identity via `webauthn`.
 */
export async function create (
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
):Promise<{ localID:string, record:Identity, keys:LockKey }> {
    const abortToken = new AbortController()
    const opts = Object.assign({
        username: 'local-user',
        displayName: 'Local User',
        relyingPartyID: document.location.hostname,
        relyingPartyName: 'wacg'
    }, _opts)
    const { username, displayName, relyingPartyID, relyingPartyName } = opts

    let result:{ localID:string, record:Identity, keys:LockKey }
    try {
        const localID:string = toBase64String(generateEntropy(15))
        const lastSeq:number = 0

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
            localID,
            keys: lockKey,
        }

        /**
         * Save the new ID to local storage
         */
        // await pushLocalIdentity(localID, result.record)
        // return { [localID]: result }
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

        const regOpt = regOptions[credentialTypeKey]  // 'publicKey'
        debug('reg opt', regOpt)

        // ensure credential IDs are binary (not base64 string)
        regOptions[regOpt].excludeCredentials = (
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

// @ts-expect-error dev
window.getKeys = getKeys

/**
 * Find an existing keypair and return it.
 */
export async function getKeys (
    localID:string
):Promise<{ record:Identity, keys:LockKey }> {
    const ids = await localIdentities()
    const identityRecord = (await localIdentities())[localID]
    if (!identityRecord) throw new Error("Can't find that identity")

    const id = ids[localID]

    const authRes = await auth(authDefaults())
    const lockKey = extractLockKey(authRes)

    return { record: id, keys: lockKey }
}

// @ts-expect-error dev
window.auth = auth

interface AuthDefaults {
    [credentialTypeKey]: 'publicKey';
    allowCredentials;
    publicKey: PublicKeyCredentialRequestOptions;
}

/**
 * Authenticate as an existing user.
 */
async function auth (
    opts:AuthDefaults = authDefaults()
):Promise<AuthResult> {
    if (!supportsWebAuthn()) {
        throw new Error('no webauthn')
    }

    // ensure credential IDs are binary (not base64 string)
    opts.allowCredentials = (
        normalizeCredentialsList(opts.allowCredentials)
    )

    debug('opts over here', opts)
    const authResult = (await navigator.credentials.get({
        publicKey: opts.publicKey
    }) as (PublicKeyCredential & {
        response:AuthenticatorAssertionResponse & { userHandle },
    })|null)

    debug('auth result', authResult)
    if (!authResult) throw new Error('not auth result')

    debug('auth response client data', authResult.response.clientDataJSON)

    const authClientDataRaw = new Uint8Array(authResult.response.clientDataJSON)
    const authClientData = JSON.parse(toUTF8String(authClientDataRaw))
    debug('parsed data', authClientData)
    if (authClientData.type !== 'webauthn.get') {
        throw new Error('Invalid auth response')
    }

    debug('opts', opts)
    debug('credential type key', credentialTypeKey)
    debug('opts cred type', opts[credentialTypeKey])

    const expectedChallenge = sodium.to_base64(
        opts[opts[credentialTypeKey]].challenge,
        sodium.base64_variants.URLSAFE_NO_PADDING
    )
    if (authClientData.challenge !== expectedChallenge) {
        throw new Error('Challenge not accepted')
    }

    const authDataRaw = new Uint8Array(
        (authResult.response as AuthenticatorAssertionResponse).authenticatorData
    )
    const authData = parseAuthenticatorData(authDataRaw)
    if (!checkRPID(authData.rpIdHash, opts.rpId)) {
        throw new Error('Unexpected relying-party ID')
    }

    // // sign-count not supported by this authenticator?
    // if (authData.signCount === 0) {
    //     delete authData.signCount;
    // }

    const signatureRaw = new Uint8Array(
        (authResult.response as AuthenticatorAssertionResponse).signature
    )

    return {
        request: {
            credentialType: authResult.type,
            ...opts[opts[credentialTypeKey]],
            ...(Object.fromEntries(
                Object.entries(authClientData).filter(([key]) => (
                    ['origin', 'crossOrigin',].includes(key)
                ))
            )),
        },
        response: {
            credentialID: toBase64String(new Uint8Array(authResult.rawId)),
            signature: signatureRaw,
            ...(Object.fromEntries(
                Object.entries(authData).filter(([key]) => (
                    ['flags', 'signCount', 'userPresence',
                        'userVerification',].includes(key)
                ))
            )),
            ...({ userID: new Uint8Array(authResult.response.userHandle) }),
            raw: authResult.response as AuthenticatorAssertionResponse,
        },
    }
}

export function encrypt (
    data:JSONValue,
    lockKey:LockKey,
    opts:{
        outputFormat:'base64'|'raw'
    } = { outputFormat: 'base64' }
):Uint8Array|string {  // return type depends on the given output format
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

// @ts-expect-error dev
window.authDefaults = authDefaults

function authDefaults ({
    credentialType = 'publicKey',
    relyingPartyID = document.location.hostname,
    userVerification = 'required' as UserVerificationRequirement,
    challenge = sodium.randombytes_buf(20),
    allowCredentials = [
        // { type: "public-key", id: ..., }
    ],
    // mediation = 'optional',
    signal: cancelAuthSignal,
    ...otherOptions
} = {
    signal: null,
}):AuthDefaults {
    const defaults = {
        publicKey: {
            rpId: relyingPartyID,
            userVerification,
            challenge,
            allowCredentials,
        },
        [credentialTypeKey]: 'publicKey',
        allowCredentials,
        // mediation,
        ...(cancelAuthSignal != null ? { signal: cancelAuthSignal, } : null),
        ...otherOptions
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

function extractLockKey (authResult:AuthResult):LockKey {
    debug('extracting the key', authResult)

    try {
        if (
            authResult &&
            authResult.response &&
            isByteArray(authResult.response.userID) &&
            authResult.response.userID.byteLength === (IV_BYTE_LENGTH + 2)
        ) {
            const lockKey = deriveLockKey(
                authResult.response.userID.subarray(0, IV_BYTE_LENGTH)
            )
            return lockKey
        } else {
            throw new Error('Passkey info missing')
        }
    } catch (err) {
        throw new Error('Chosen passkey did not provide a valid encryption/decryption key', { cause: err, })
    }
}
