const PBKDF2_ITERATIONS = 200_000;
const PBKDF2_KEY_BYTES = 32;
const LEGACY_ENCRYPT_KEY = 30;

const ENCRYPTION_KEY_DOMAIN = 'pwprot-v1-encrypt';

export interface PasswordData {
    version: 2;
    salt: string;
    hash: string;
}

export function bufToBase64(buf: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < buf.length; i++) binary += String.fromCharCode(buf[i]);
    return btoa(binary);
}

export function base64ToBuf(b64: string): Uint8Array {
    const binary = atob(b64);
    const buf = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) buf[i] = binary.charCodeAt(i);
    return buf;
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
}

export async function deriveKey(password: string, salt: Uint8Array): Promise<Uint8Array> {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        enc.encode(password),
        'PBKDF2',
        false,
        ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        { name: 'PBKDF2', salt: salt as any, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
        keyMaterial,
        PBKDF2_KEY_BYTES * 8
    );
    return new Uint8Array(bits);
}

// Domain-separates the bytes used for AES-GCM key derivation from the bytes
// stored on disk as the verification hash. An attacker who reads data.json
// gets the raw PBKDF2 output (the verification hash) but not the encryption
// key, which is HMAC-SHA256(rawPbkdf2, "pwprot-v1-encrypt").
export async function deriveEncryptionKey(password: string, salt: Uint8Array): Promise<Uint8Array> {
    const raw = await deriveKey(password, salt);
    const hmacKey = await crypto.subtle.importKey(
        'raw',
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        raw as any,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', hmacKey, new TextEncoder().encode(ENCRYPTION_KEY_DOMAIN));
    return new Uint8Array(sig);
}

export async function hashPassword(password: string): Promise<PasswordData> {
    const salt = crypto.getRandomValues(new Uint8Array(new ArrayBuffer(16)));
    const hash = await deriveKey(password, salt);
    return { version: 2, salt: bufToBase64(salt), hash: bufToBase64(hash) };
}

export async function verifyPasswordHash(password: string, data: PasswordData): Promise<boolean> {
    const salt = base64ToBuf(data.salt);
    const derived = await deriveKey(password, salt);
    return timingSafeEqual(derived, base64ToBuf(data.hash));
}

export function legacyVerify(inputPassword: string, storedCipher: string): boolean {
    let result = '';
    for (let i = 0; i < storedCipher.length; i++) {
        const charCode = storedCipher.charCodeAt(i);
        if (charCode >= 33 && charCode <= 90) {
            result += String.fromCharCode(((charCode - 33 - LEGACY_ENCRYPT_KEY + 58) % 58) + 33);
        } else if (charCode >= 91 && charCode <= 126) {
            result += String.fromCharCode(((charCode - 91 - LEGACY_ENCRYPT_KEY + 36) % 36) + 91);
        } else {
            result += storedCipher.charAt(i);
        }
    }
    return inputPassword === result;
}
