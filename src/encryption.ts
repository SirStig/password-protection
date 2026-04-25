import { bufToBase64, base64ToBuf } from './crypto';

export const ENCRYPTED_FENCE_LANG = 'pwprot-v1';
const PER_FILE_KEY_DOMAIN = 'pwprot-v1-file';

export const ENCRYPTED_HEADER_PREAMBLE =
    '> [!warning] Noteguard — encrypted note\n' +
    '> This file is encrypted by the **Noteguard** Obsidian plugin.\n' +
    '> Do not edit it in another editor or it will become unreadable.\n' +
    '> Open it in Obsidian and unlock to view its contents.\n\n';

export interface EncryptedEnvelope {
    version: 1;
    salt: string;       // base64 of 16 random bytes
    iv: string;         // base64 of 12 random bytes (per-save)
    ciphertext: string; // base64 of AES-GCM output (ciphertext + 16-byte AEAD tag)
}

export type EnvelopeErrorCode =
    | 'no-fence'
    | 'no-close'
    | 'bad-base64'
    | 'bad-json'
    | 'bad-version';

export class EnvelopeError extends Error {
    constructor(public readonly code: EnvelopeErrorCode, message: string) {
        super(message);
        this.name = 'EnvelopeError';
    }
}

export type DecryptionErrorCode = 'auth-failed' | 'malformed';

export class DecryptionError extends Error {
    constructor(public readonly code: DecryptionErrorCode, message: string) {
        super(message);
        this.name = 'DecryptionError';
    }
}

const FENCE_OPEN_RE = /^```pwprot-v1[ \t]*$/m;
const FENCE_CLOSE_RE = /^```[ \t]*$/m;

export function isEncryptedFile(body: string): boolean {
    return FENCE_OPEN_RE.test(body);
}

export function parseEnvelope(body: string): EncryptedEnvelope {
    const open = body.match(FENCE_OPEN_RE);
    if (!open || open.index === undefined) {
        throw new EnvelopeError('no-fence', 'No pwprot-v1 fence found.');
    }
    const afterOpen = body.indexOf('\n', open.index + open[0].length);
    if (afterOpen < 0) {
        throw new EnvelopeError('no-close', 'pwprot-v1 fence has no body.');
    }
    const remainder = body.substring(afterOpen + 1);
    const close = remainder.match(FENCE_CLOSE_RE);
    if (!close || close.index === undefined) {
        throw new EnvelopeError('no-close', 'pwprot-v1 fence is not closed.');
    }
    const inner = remainder.substring(0, close.index).trim();

    let json: string;
    try {
        json = atob(inner);
    } catch {
        throw new EnvelopeError('bad-base64', 'Envelope payload is not valid base64.');
    }

    let parsed: unknown;
    try {
        parsed = JSON.parse(json);
    } catch {
        throw new EnvelopeError('bad-json', 'Envelope payload is not valid JSON.');
    }
    if (!parsed || typeof parsed !== 'object') {
        throw new EnvelopeError('bad-json', 'Envelope payload is not an object.');
    }
    const obj = parsed as Record<string, unknown>;
    if (obj.v !== 1) {
        throw new EnvelopeError('bad-version', `Unsupported envelope version: ${String(obj.v)}.`);
    }
    if (
        typeof obj.salt !== 'string' ||
        typeof obj.iv !== 'string' ||
        typeof obj.ct !== 'string'
    ) {
        throw new EnvelopeError('bad-json', 'Envelope is missing salt/iv/ct fields.');
    }
    return { version: 1, salt: obj.salt, iv: obj.iv, ciphertext: obj.ct };
}

export function serializeEnvelope(env: EncryptedEnvelope): string {
    const json = JSON.stringify({ v: env.version, salt: env.salt, iv: env.iv, ct: env.ciphertext });
    const b64 = bufToBase64(new TextEncoder().encode(json));
    return `${ENCRYPTED_HEADER_PREAMBLE}\`\`\`${ENCRYPTED_FENCE_LANG}\n${b64}\n\`\`\`\n`;
}

// HMAC-SHA256(masterEncKey, salt || "pwprot-v1-file") — gives every file
// its own AES key so an IV collision across files cannot yield (key, iv) reuse.
async function derivePerFileKey(masterEncKey: Uint8Array, salt: Uint8Array): Promise<CryptoKey> {
    const domain = new TextEncoder().encode(PER_FILE_KEY_DOMAIN);
    const message = new Uint8Array(salt.length + domain.length);
    message.set(salt, 0);
    message.set(domain, salt.length);

    const hmacKey = await crypto.subtle.importKey(
        'raw',
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        masterEncKey as any,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', hmacKey, message);
    const raw = new Uint8Array(sig);

    return crypto.subtle.importKey(
        'raw',
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        raw as any,
        'AES-GCM',
        false,
        ['encrypt', 'decrypt']
    );
}

export async function encryptNote(plaintext: string, masterEncKey: Uint8Array): Promise<string> {
    const salt = crypto.getRandomValues(new Uint8Array(new ArrayBuffer(16)));
    const iv = crypto.getRandomValues(new Uint8Array(new ArrayBuffer(12)));
    const aesKey = await derivePerFileKey(masterEncKey, salt);
    const ctBuf = await crypto.subtle.encrypt(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        { name: 'AES-GCM', iv: iv as any },
        aesKey,
        new TextEncoder().encode(plaintext)
    );
    return serializeEnvelope({
        version: 1,
        salt: bufToBase64(salt),
        iv: bufToBase64(iv),
        ciphertext: bufToBase64(new Uint8Array(ctBuf)),
    });
}

export async function decryptNote(fileBody: string, masterEncKey: Uint8Array): Promise<string> {
    const env = parseEnvelope(fileBody);
    let salt: Uint8Array;
    let iv: Uint8Array;
    let ct: Uint8Array;
    try {
        salt = base64ToBuf(env.salt);
        iv = base64ToBuf(env.iv);
        ct = base64ToBuf(env.ciphertext);
    } catch {
        throw new DecryptionError('malformed', 'Envelope contains invalid base64.');
    }
    const aesKey = await derivePerFileKey(masterEncKey, salt);
    let ptBuf: ArrayBuffer;
    try {
        ptBuf = await crypto.subtle.decrypt(
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            { name: 'AES-GCM', iv: iv as any },
            aesKey,
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            ct as any
        );
    } catch {
        throw new DecryptionError(
            'auth-failed',
            'AES-GCM authentication failed (wrong password or tampered file).'
        );
    }
    return new TextDecoder().decode(ptBuf);
}
