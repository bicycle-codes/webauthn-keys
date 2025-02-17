export interface PassKeyPublicKey {
    algoCOSE:COSEAlgorithmIdentifier;
    algoOID:string;
    raw:Uint8Array|string;
    spki:Uint8Array|string;
}

export interface Passkey {
    credentialID:string;
    seq:number;
    publicKey:PassKeyPublicKey;
    hash:string;
}

export interface Identity {
    lastSeq:number;
    passkeys:Passkey[];
}

export type COSE = -8|-7|-37|-257

export interface RegistrationResult {
    // request:any;
    request:PublicKeyCredentialRequestOptions;
    // response:AuthenticatorAttestationResponse;
    response:{
        credentialID:string;
        credentialType:PublicKeyCredential['type'];
        authenticatorAttachment:string|null;
        publicKey: {
            algoCOSE:COSEAlgorithmIdentifier;
            algoOID:string;
            spki:Uint8Array;
            raw:Uint8Array;
        },
        raw:AuthenticatorResponse;
    };
}

export type AuthResponse = PublicKeyCredential & {
    response:AuthenticatorAssertionResponse
}

export interface LockKey {
    keyFormatVersion:number;
    iv:Uint8Array;
    publicKey:Uint8Array;
    privateKey:Uint8Array;
    encPK:Uint8Array;
    encSK:Uint8Array;
}

export type JSONPrimitive = string | number | boolean | null | undefined;

export type JSONValue = JSONPrimitive | JSONValue[] | {
    [key: string]: JSONValue;
};
