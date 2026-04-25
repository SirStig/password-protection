import { describe, expect, it } from 'vitest';
import {
    encryptNote,
    decryptNote,
    isEncryptedFile,
    parseEnvelope,
    serializeEnvelope,
    EnvelopeError,
    DecryptionError,
    ENCRYPTED_FENCE_LANG,
} from '../src/encryption';
import { bufToBase64 } from '../src/crypto';

function makeKey(seed = 0x42): Uint8Array {
    const k = new Uint8Array(32);
    for (let i = 0; i < k.length; i++) k[i] = (seed + i) & 0xff;
    return k;
}

describe('encryptNote / decryptNote', () => {
    it('round-trips ASCII', async () => {
        const k = makeKey();
        const ct = await encryptNote('hello world', k);
        const pt = await decryptNote(ct, k);
        expect(pt).toBe('hello world');
    });

    it('round-trips UTF-8 with emoji and CJK', async () => {
        const k = makeKey();
        const text = 'Hello 🌍 — 你好 こんにちは 🔐';
        const ct = await encryptNote(text, k);
        const pt = await decryptNote(ct, k);
        expect(pt).toBe(text);
    });

    it('round-trips a long markdown document', async () => {
        const k = makeKey(0x7);
        const text = `# Title\n\nParagraph with *emphasis* and **strong**.\n\n- one\n- two\n- three\n\n\`\`\`ts\nconst x = 1;\n\`\`\`\n`.repeat(50);
        const ct = await encryptNote(text, k);
        const pt = await decryptNote(ct, k);
        expect(pt).toBe(text);
    });

    it('produces a fresh IV on every encrypt', async () => {
        const k = makeKey();
        const a = await encryptNote('same text', k);
        const b = await encryptNote('same text', k);
        expect(a).not.toBe(b);
        expect(parseEnvelope(a).iv).not.toBe(parseEnvelope(b).iv);
        expect(parseEnvelope(a).salt).not.toBe(parseEnvelope(b).salt);
    });

    it('decryption with the wrong key throws auth-failed', async () => {
        const k1 = makeKey(1);
        const k2 = makeKey(2);
        const ct = await encryptNote('secret', k1);
        await expect(decryptNote(ct, k2)).rejects.toBeInstanceOf(DecryptionError);
        try {
            await decryptNote(ct, k2);
            throw new Error('expected throw');
        } catch (e) {
            expect((e as DecryptionError).code).toBe('auth-failed');
        }
    });

    it('decryption of a tampered ciphertext throws auth-failed', async () => {
        const k = makeKey();
        const ct = await encryptNote('secret', k);
        const env = parseEnvelope(ct);
        // Flip one bit of the ciphertext base64 by mangling its first chars.
        const flipped = env.ciphertext.startsWith('A')
            ? 'B' + env.ciphertext.slice(1)
            : 'A' + env.ciphertext.slice(1);
        const tampered = serializeEnvelope({ ...env, ciphertext: flipped });
        await expect(decryptNote(tampered, k)).rejects.toBeInstanceOf(DecryptionError);
    });

    it('output starts with the visible warning callout', async () => {
        const k = makeKey();
        const ct = await encryptNote('any', k);
        expect(ct.startsWith('> [!warning] Noteguard')).toBe(true);
    });

    it('output contains the pwprot-v1 fence', async () => {
        const k = makeKey();
        const ct = await encryptNote('any', k);
        expect(ct).toMatch(/^```pwprot-v1$/m);
    });
});

describe('isEncryptedFile', () => {
    it('recognises a freshly encrypted note', async () => {
        const ct = await encryptNote('x', makeKey());
        expect(isEncryptedFile(ct)).toBe(true);
    });

    it('rejects plain markdown', () => {
        expect(isEncryptedFile('# Heading\n\nplain text.')).toBe(false);
    });

    it('rejects a near-miss fence with a different version', () => {
        const body = '```pwprot-v0\nAAAA\n```\n';
        expect(isEncryptedFile(body)).toBe(false);
    });

    it('rejects a near-miss fence without the dash-version', () => {
        const body = '```pwprotv1\nAAAA\n```\n';
        expect(isEncryptedFile(body)).toBe(false);
    });

    it('still recognises an encrypted file embedded after other content', () => {
        const body = `Some preamble.\n\n\`\`\`pwprot-v1\nAAAA\n\`\`\`\n`;
        expect(isEncryptedFile(body)).toBe(true);
    });
});

describe('parseEnvelope errors', () => {
    it('throws no-fence on plain markdown', () => {
        try {
            parseEnvelope('# nothing to see\n');
            throw new Error('expected throw');
        } catch (e) {
            expect(e).toBeInstanceOf(EnvelopeError);
            expect((e as EnvelopeError).code).toBe('no-fence');
        }
    });

    it('throws no-close when fence is unterminated', () => {
        const body = '```pwprot-v1\nAAAA';
        try {
            parseEnvelope(body);
            throw new Error('expected throw');
        } catch (e) {
            expect((e as EnvelopeError).code).toBe('no-close');
        }
    });

    it('throws bad-json when payload is not JSON', () => {
        const b64 = bufToBase64(new TextEncoder().encode('not-json'));
        const body = `\`\`\`pwprot-v1\n${b64}\n\`\`\`\n`;
        try {
            parseEnvelope(body);
            throw new Error('expected throw');
        } catch (e) {
            expect((e as EnvelopeError).code).toBe('bad-json');
        }
    });

    it('throws bad-version when v != 1', () => {
        const json = JSON.stringify({ v: 2, salt: 'AAAA', iv: 'BBBB', ct: 'CCCC' });
        const b64 = bufToBase64(new TextEncoder().encode(json));
        const body = `\`\`\`pwprot-v1\n${b64}\n\`\`\`\n`;
        try {
            parseEnvelope(body);
            throw new Error('expected throw');
        } catch (e) {
            expect((e as EnvelopeError).code).toBe('bad-version');
        }
    });
});

describe('serializeEnvelope', () => {
    it('emits the canonical layout exactly', () => {
        const out = serializeEnvelope({
            version: 1,
            salt: 'AAAA',
            iv: 'BBBB',
            ciphertext: 'CCCC',
        });
        expect(out).toContain('> [!warning] Noteguard');
        expect(out).toMatch(/^```pwprot-v1$/m);
        expect(out).toContain(ENCRYPTED_FENCE_LANG);
    });

    it('round-trips through parseEnvelope', () => {
        const env = { version: 1 as const, salt: 'AAAA', iv: 'BBBB', ciphertext: 'CCCC' };
        const out = serializeEnvelope(env);
        expect(parseEnvelope(out)).toEqual(env);
    });
});
