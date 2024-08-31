export interface PassKeyPublicKey {
    algoCOSE:number;
    raw:string;
    spki:string;
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
    request:any;
    response: {
        credentialID:string;
        credentialType:PublicKeyCredential['type'];
        authenticatorAttachment:string|null;
        publicKey: {
            algoCOSE:COSEAlgorithmIdentifier;
            algoOID:string;
            spki:Uint8Array;
            raw:Uint8Array|null;
        },
        raw:AuthenticatorResponse;
    };
}
