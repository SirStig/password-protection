import { App, TFile, DataWriteOptions, Notice } from 'obsidian';
import type { TransItemType } from '../i18n';
import { isEncryptedFile, encryptNote, decryptNote, DecryptionError } from './encryption';
import { modeForFile } from './path-utils';
import type { PasswordPluginSettings } from './settings';

// Minimal structural interface — avoids a circular import on the
// PasswordPlugin class while still letting the patches reach the in-memory
// key, the lock state, and i18n.
export interface PatchablePlugin {
    app: App;
    settings: PasswordPluginSettings;
    encryptionKey: Uint8Array | null;
    isVerifyPasswordCorrect: boolean;
    requireEncryptionKey(): Uint8Array;
    t(key: TransItemType, vars?: Record<string, string>): string;
}

export interface VaultPatchHandle {
    uninstall(): void;
    // Bound originals exposed for bulk ops that must read/write raw on-disk
    // bytes (the wrappers would otherwise transparently decrypt/encrypt).
    originalRead(file: TFile): Promise<string>;
    originalCachedRead(file: TFile): Promise<string>;
    originalModify(file: TFile, data: string, options?: DataWriteOptions): Promise<void>;
}

const isMd = (file: TFile) => file.extension === 'md';

export function installVaultPatches(plugin: PatchablePlugin): VaultPatchHandle {
    const vault = plugin.app.vault;
    const v = vault as unknown as Record<string, unknown>;

    const originalRead = vault.read.bind(vault);
    const originalCachedRead = vault.cachedRead.bind(vault);
    const originalModify = vault.modify.bind(vault);
    const originalProcess = vault.process.bind(vault);
    const originalCreate = vault.create.bind(vault);

    const decryptIfNeeded = async (raw: string, file: TFile): Promise<string> => {
        if (!plugin.settings.protectEnabled) return raw;
        if (!isEncryptedFile(raw)) return raw;
        if (!plugin.encryptionKey) {
            // Locked — pass ciphertext through. The existing UI gate
            // triggers the verify modal anyway, so users rarely see this;
            // when they do, they see the warning callout in the file.
            return raw;
        }
        try {
            return await decryptNote(raw, plugin.encryptionKey);
        } catch (e) {
            if (e instanceof DecryptionError) {
                new Notice(plugin.t('notice_decrypt_failed', { path: file.path }));
                console.error(`pwprot: failed to decrypt ${file.path}`, e);
            }
            return raw;
        }
    };

    // Decide what to actually persist. The encryption status of an *existing*
    // file is intrinsic to its on-disk sentinel, so encryption follows the
    // file regardless of whether it is currently inside a protected folder.
    const wrapModifyData = async (file: TFile, newData: string): Promise<string> => {
        if (!plugin.settings.protectEnabled) return newData;
        let onDisk: string;
        try {
            onDisk = await originalRead(file);
        } catch {
            return newData;
        }
        if (!isEncryptedFile(onDisk)) return newData;
        if (!plugin.encryptionKey) {
            new Notice(plugin.t('notice_locked_write_blocked'));
            throw new Error('pwprot: refusing to overwrite an encrypted file while locked.');
        }
        return await encryptNote(newData, plugin.encryptionKey);
    };

    v.read = async function (file: TFile): Promise<string> {
        const raw = await originalRead(file);
        if (!isMd(file)) return raw;
        return decryptIfNeeded(raw, file);
    };

    v.cachedRead = async function (file: TFile): Promise<string> {
        const raw = await originalCachedRead(file);
        if (!isMd(file)) return raw;
        return decryptIfNeeded(raw, file);
    };

    v.modify = async function (
        file: TFile,
        data: string,
        options?: DataWriteOptions
    ): Promise<void> {
        if (!isMd(file)) return originalModify(file, data, options);
        const final = await wrapModifyData(file, data);
        return originalModify(file, final, options);
    };

    // Wrap `process` so the user callback sees plaintext both for the input
    // it receives and for the output Obsidian persists. Obsidian's typings
    // declare `fn` as sync but in practice it awaits the return value, which
    // lets us decrypt → fn → encrypt asynchronously inside a single atomic
    // process call.
    v.process = async function (
        file: TFile,
        fn: (data: string) => string,
        options?: DataWriteOptions
    ): Promise<string> {
        if (!isMd(file) || !plugin.settings.protectEnabled) {
            return originalProcess(file, fn, options);
        }
        return originalProcess(
            file,
            ((raw: string) => {
                if (!isEncryptedFile(raw)) return fn(raw);
                if (!plugin.encryptionKey) {
                    new Notice(plugin.t('notice_locked_write_blocked'));
                    throw new Error(
                        'pwprot: refusing to process an encrypted file while locked.'
                    );
                }
                return (async () => {
                    const key = plugin.requireEncryptionKey();
                    const plaintext = await decryptNote(raw, key);
                    const updated = await Promise.resolve(fn(plaintext));
                    return await encryptNote(updated, key);
                })() as unknown as string;
            }) as (data: string) => string,
            options
        );
    };

    v.create = async function (
        path: string,
        data: string,
        options?: DataWriteOptions
    ): Promise<TFile> {
        if (!plugin.settings.protectEnabled || !path.toLowerCase().endsWith('.md')) {
            return originalCreate(path, data, options);
        }
        const folderMode = modeForFile(path, plugin.settings.paths);
        if (folderMode === 'encrypted') {
            if (!plugin.encryptionKey) {
                new Notice(plugin.t('notice_locked_write_blocked'));
                throw new Error(
                    'pwprot: refusing to create a file in an encrypted folder while locked.'
                );
            }
            const ct = await encryptNote(data, plugin.encryptionKey);
            return originalCreate(path, ct, options);
        }
        return originalCreate(path, data, options);
    };

    return {
        uninstall: () => {
            v.read = originalRead;
            v.cachedRead = originalCachedRead;
            v.modify = originalModify;
            v.process = originalProcess;
            v.create = originalCreate;
        },
        originalRead,
        originalCachedRead,
        originalModify,
    };
}
