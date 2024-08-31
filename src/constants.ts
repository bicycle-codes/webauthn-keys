/**
 * NOTE: these are ordered by "preference" for key
 * generation by WebAuthn create()
 */
export const PUBLIC_KEY_ALGORITHMS = [
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
]
