import { App, TFile } from 'obsidian';
import { isEncryptedFile, encryptNote, decryptNote } from './encryption';
import { isChildPath, ROOT_PATH } from './path-utils';
import type { VaultPatchHandle } from './vault-patch';

export type BulkPhase = 'encrypt' | 'decrypt' | 'reencrypt';

export interface BulkResult {
    ok: number;
    skipped: number;
    failed: { path: string; error: string }[];
    aborted: boolean;
    total: number;
}

export interface BulkProgress {
    total: number;
    processed: number;
    current: string;
    phase: BulkPhase;
}

export type BulkProgressCallback = (p: BulkProgress) => void;

// Walks every Markdown file under `folderPath` (vault-wide for ROOT_PATH).
// Sorted by path for stable, resumable iteration.
function filesUnder(app: App, folderPath: string): TFile[] {
    const isAll = folderPath === ROOT_PATH || folderPath === '';
    return app.vault
        .getMarkdownFiles()
        .filter((f) => isAll || isChildPath(f.path, folderPath))
        .sort((a, b) => a.path.localeCompare(b.path));
}

async function runBulk(
    files: TFile[],
    phase: BulkPhase,
    handle: (file: TFile) => Promise<'ok' | 'skipped'>,
    onProgress?: BulkProgressCallback,
    signal?: AbortSignal
): Promise<BulkResult> {
    const result: BulkResult = {
        ok: 0,
        skipped: 0,
        failed: [],
        aborted: false,
        total: files.length,
    };
    for (let i = 0; i < files.length; i++) {
        if (signal?.aborted) {
            result.aborted = true;
            break;
        }
        const file = files[i];
        try {
            const r = await handle(file);
            if (r === 'ok') result.ok++;
            else result.skipped++;
        } catch (e) {
            result.failed.push({
                path: file.path,
                error: e instanceof Error ? e.message : String(e),
            });
        }
        onProgress?.({
            total: files.length,
            processed: i + 1,
            current: file.path,
            phase,
        });
    }
    return result;
}

export async function countEncryptedInFolder(
    app: App,
    folderPath: string,
    patches: VaultPatchHandle,
    signal?: AbortSignal
): Promise<{ total: number; encrypted: number }> {
    const files = filesUnder(app, folderPath);
    let encrypted = 0;
    for (const file of files) {
        if (signal?.aborted) break;
        try {
            const raw = await patches.originalRead(file);
            if (isEncryptedFile(raw)) encrypted++;
        } catch {
            // ignore unreadable files
        }
    }
    return { total: files.length, encrypted };
}

export async function countEncryptedVaultWide(
    app: App,
    patches: VaultPatchHandle,
    signal?: AbortSignal
): Promise<{ total: number; encrypted: number }> {
    return countEncryptedInFolder(app, ROOT_PATH, patches, signal);
}

export async function encryptFolder(
    app: App,
    folderPath: string,
    key: Uint8Array,
    patches: VaultPatchHandle,
    onProgress?: BulkProgressCallback,
    signal?: AbortSignal
): Promise<BulkResult> {
    const files = filesUnder(app, folderPath);
    return runBulk(
        files,
        'encrypt',
        async (file) => {
            const raw = await patches.originalRead(file);
            if (isEncryptedFile(raw)) return 'skipped';
            const ct = await encryptNote(raw, key);
            await patches.originalModify(file, ct);
            return 'ok';
        },
        onProgress,
        signal
    );
}

export async function decryptFolder(
    app: App,
    folderPath: string,
    key: Uint8Array,
    patches: VaultPatchHandle,
    onProgress?: BulkProgressCallback,
    signal?: AbortSignal
): Promise<BulkResult> {
    const files = filesUnder(app, folderPath);
    return runBulk(
        files,
        'decrypt',
        async (file) => {
            const raw = await patches.originalRead(file);
            if (!isEncryptedFile(raw)) return 'skipped';
            const pt = await decryptNote(raw, key);
            await patches.originalModify(file, pt);
            return 'ok';
        },
        onProgress,
        signal
    );
}

// Re-encrypts every encrypted file in the vault using `newKey`. Idempotent
// across crashes: if a file already decrypts with `newKey` it is treated as
// already-migrated and skipped. Otherwise it is decrypted with `oldKey` and
// rewritten with `newKey`.
export async function reencryptAll(
    app: App,
    oldKey: Uint8Array,
    newKey: Uint8Array,
    patches: VaultPatchHandle,
    onProgress?: BulkProgressCallback,
    signal?: AbortSignal
): Promise<BulkResult> {
    const files = filesUnder(app, ROOT_PATH);
    return runBulk(
        files,
        'reencrypt',
        async (file) => {
            const raw = await patches.originalRead(file);
            if (!isEncryptedFile(raw)) return 'skipped';
            try {
                await decryptNote(raw, newKey);
                return 'skipped';
            } catch {
                // fall through — try the old key
            }
            const pt = await decryptNote(raw, oldKey);
            const ct = await encryptNote(pt, newKey);
            await patches.originalModify(file, ct);
            return 'ok';
        },
        onProgress,
        signal
    );
}

// Single-file helpers for the per-file menu/command. Both no-op and return
// the prior state if the file was already in the target state.
export async function encryptSingleFile(
    file: TFile,
    key: Uint8Array,
    patches: VaultPatchHandle
): Promise<'encrypted' | 'already-encrypted'> {
    const raw = await patches.originalRead(file);
    if (isEncryptedFile(raw)) return 'already-encrypted';
    const ct = await encryptNote(raw, key);
    await patches.originalModify(file, ct);
    return 'encrypted';
}

export async function decryptSingleFile(
    file: TFile,
    key: Uint8Array,
    patches: VaultPatchHandle
): Promise<'decrypted' | 'already-plaintext'> {
    const raw = await patches.originalRead(file);
    if (!isEncryptedFile(raw)) return 'already-plaintext';
    const pt = await decryptNote(raw, key);
    await patches.originalModify(file, pt);
    return 'decrypted';
}
