export type RSAKey = {
    n: any;
    e: any;
    d: any;
    p: any;
    q: any;
    dmp1: any;
    dmq1: any;
    coeff: any;
    doPublic(x: any): any;
    doPrivate(x: any): any;
    setPublic(N: any, E: any): any;
    encrypt(text: string): string;
    setPrivate(N: any, E: any, D: any): any;
    setPrivateEx(
        N: any,
        E: any,
        D: any,
        P: any,
        Q: any,
        DP: any,
        DQ: any,
        C: any
    ): any;
    generate(B: any, E: any): any;
    decrypt(ctext: string): string;
    signString(s: any, hashAlg: any): any;
    signStringWithSHA1(s: any): any;
    signStringWithSHA256(s: any): any;
    verifyString(sMsg: any, hSig: any): any;
    verifyHexSignatureForMessage(hSig: any, sMsg: any): any;
    toJSON(): {
        coeff: string;
        d: string;
        dmp1: string;
        dmq1: string;
        e: string;
        n: string;
        p: string;
        q: string;
    };
};

type Status = 'success' | string;

interface EncryptResult {
    cipher: string;
    status: Status;
}
interface DecryptResult {
    plaintext: string;
    publicKeyString: string;
    signature: 'verified' | string;
    status: Status;
}

export interface ICryptico {
    encrypt(
        plaintext: string,
        publickeystring: string,
        signingkey: RSAKey
    ): EncryptResult;
    decrypt(ciphertext: string, key: RSAKey): DecryptResult;
    publicKeyString(rsakey: RSAKey): string;
}
