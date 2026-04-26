import {
    App,
    normalizePath,
    Menu,
    Modal,
    EventRef,
    MarkdownRenderChild,
    MarkdownView,
    Notice,
    Plugin,
    PluginSettingTab,
    Setting,
    TAbstractFile,
    TFile,
    TFolder,
    WorkspaceLeaf,
    FileView,
    moment,
} from 'obsidian';
import { I18n } from './i18n';
import type { LangTypeAndAuto, TransItemType } from './i18n';
import {
    hashPassword,
    verifyPasswordHash,
    legacyVerify,
    deriveEncryptionKey,
    base64ToBuf,
} from './src/crypto';
import {
    ROOT_PATH,
    isProtectedByEntries,
    anyEntryIsRoot,
    replaceProtectedPathInEntries,
} from './src/path-utils';
import {
    PasswordPluginSettings,
    migrateSettings,
    mirrorPathsToLegacy,
} from './src/settings';
import { PathPickerModal } from './src/path-picker';
import { addHelpIcon } from './src/help-modal';
import { isEncryptedFile } from './src/encryption';
import { installVaultPatches, VaultPatchHandle } from './src/vault-patch';
import {
    BulkProgress,
    BulkProgressCallback,
    BulkResult,
    countEncryptedInFolder,
    countEncryptedVaultWide,
    decryptFolder,
    decryptSingleFile,
    encryptFolder,
    encryptSingleFile,
    reencryptAll,
} from './src/bulk-ops';
import { ProtectionMode, ProtectedPathEntry } from './src/path-utils';

const PASSWORD_LENGTH_MIN = 1;
const PASSWORD_LENGTH_MAX = 20;

// View types that aggregate content and may expose protected note excerpts.
const AGGREGATE_VIEW_TYPES = new Set(['search', 'backlink', 'outgoing-link', 'tag']);

function isUnlockContextLeaf(leaf: WorkspaceLeaf, plugin: PasswordPlugin): boolean {
    if (leaf.view instanceof FileView && leaf.view.file) {
        return plugin.isProtectedFile(leaf.view.file.path);
    }
    return AGGREGATE_VIEW_TYPES.has(leaf.view.getViewType());
}

async function verifyPluginPassword(
    password: string,
    plugin: PasswordPlugin
): Promise<boolean> {
    const { settings } = plugin;
    if (settings.passwordData !== null) {
        return verifyPasswordHash(password, settings.passwordData);
    }
    if (settings.password !== '') {
        const ok = legacyVerify(password, settings.password);
        if (ok) await plugin.migratePassword(password);
        return ok;
    }
    return false;
}

function createPasswordVerifyForm(
    targetEl: HTMLElement,
    plugin: PasswordPlugin,
    onSuccess: (password: string) => void | Promise<void>
) {
    targetEl.createEl('h2', { text: plugin.t('verify_password') });
    const pwWrap = targetEl.createDiv({ cls: 'pw-input-row' });
    const pwInputEl = pwWrap.createEl('input', { type: 'password' });
    pwInputEl.placeholder = plugin.t('enter_password');

    const messageEl = targetEl.createDiv({ cls: 'pw-message' });
    messageEl.setText(plugin.t('enter_password_to_verify'));

    pwInputEl.addEventListener('input', () => {
        messageEl.style.color = '';
        messageEl.setText(plugin.t('enter_password_to_verify'));
    });
    pwInputEl.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') void pwChecker();
    });

    const pwChecker = async () => {
        const pw = pwInputEl.value.normalize('NFC');
        if (!pw) {
            messageEl.style.color = 'red';
            messageEl.setText(plugin.t('password_is_empty'));
            return;
        }
        if (pw.length < PASSWORD_LENGTH_MIN || pw.length > PASSWORD_LENGTH_MAX) {
            messageEl.style.color = 'red';
            messageEl.setText(plugin.t('password_not_match'));
            return;
        }
        const ok = await verifyPluginPassword(pw, plugin);
        if (!ok) {
            messageEl.style.color = 'red';
            let text = plugin.t('password_not_match');
            const hint = plugin.settings.pwdHintQuestion;
            if (hint) text += `  ${plugin.t('setting_pwd_hint_question_name')}: ${hint}`;
            messageEl.setText(text);
            return;
        }
        await onSuccess(pw);
    };

    new Setting(targetEl).addButton((btn) =>
        btn.setButtonText(plugin.t('ok')).setCta().onClick(() => void pwChecker())
    );

    return { focus: () => pwInputEl.focus() };
}

class UnlockFallbackModal extends Modal {
    constructor(
        app: App,
        private plugin: PasswordPlugin
    ) {
        super(app);
    }

    onOpen() {
        const { contentEl } = this;
        contentEl.empty();
        createPasswordVerifyForm(contentEl, this.plugin, async (pw) => {
            this.plugin.lastUnlockOrOpenFileTime = moment();
            this.plugin.isVerifyPasswordCorrect = true;
            await this.plugin.setEncryptionKeyFromPassword(pw);
            this.close();
        }).focus();
    }

    onClose() {
        this.contentEl.empty();
        if (this.plugin.unlockSuppressNextModalOnClose) {
            this.plugin.unlockSuppressNextModalOnClose = false;
            return;
        }
        this.plugin.teardownPasswordUnlockSession(this.plugin.isVerifyPasswordCorrect, {
            skipModalClose: true,
        });
    }
}

class SettingsPasswordModal extends Modal {
    private onSubmit: () => void;
    private dismissOnNavRef: EventRef | null = null;
    private overlays: HTMLElement[] = [];

    constructor(
        app: App,
        private plugin: PasswordPlugin,
        onSubmit: () => void
    ) {
        super(app);
        this.onSubmit = onSubmit;
    }

    onOpen() {
        this.plugin.isVerifyPasswordWaitting = true;
        this.plugin.isVerifyPasswordCorrect = false;
        const bg = this.containerEl.querySelector('.modal-bg') as HTMLElement | null;
        if (bg) bg.style.pointerEvents = 'none';

        this.app.workspace.iterateAllLeaves((leaf) => {
            if (!(leaf.view instanceof FileView) || !leaf.view.file) return;
            if (!this.plugin.isProtectedFile(leaf.view.file.path)) return;
            const overlay = leaf.view.contentEl.createDiv({ cls: 'pw-leaf-overlay' });
            overlay.createDiv({ cls: 'pw-leaf-overlay-icon' }).setText('🔒');
            this.overlays.push(overlay);
        });

        this.dismissOnNavRef = this.app.workspace.on('active-leaf-change', (leaf) => {
            if (!leaf) return;
            const isContext = isUnlockContextLeaf(leaf, this.plugin);
            if (!isContext) this.close();
        });

        const { contentEl } = this;
        contentEl.empty();
        createPasswordVerifyForm(contentEl, this.plugin, async (pw) => {
            this.plugin.lastUnlockOrOpenFileTime = moment();
            this.plugin.isVerifyPasswordCorrect = true;
            await this.plugin.setEncryptionKeyFromPassword(pw);
            this.close();
        }).focus();
    }

    onClose() {
        this.plugin.isVerifyPasswordWaitting = false;
        this.contentEl.empty();
        for (const overlay of this.overlays) overlay.remove();
        this.overlays = [];
        if (this.dismissOnNavRef) {
            this.app.workspace.offref(this.dismissOnNavRef);
            this.dismissOnNavRef = null;
        }
        this.onSubmit();
    }
}

export default class PasswordPlugin extends Plugin {
    settings: PasswordPluginSettings;
    isVerifyPasswordWaitting = false;
    isVerifyPasswordCorrect = false;
    lastUnlockOrOpenFileTime: moment.Moment | null = null;
    passwordRibbonBtn: HTMLElement;
    statusBarItem: HTMLElement | null = null;
    i18n: I18n;

    // In-memory key for AES-GCM file encryption. Set on successful unlock,
    // zeroed on every transition that locks the vault. Never persisted.
    encryptionKey: Uint8Array | null = null;
    vaultPatchHandle: VaultPatchHandle | null = null;
    // Tracks per-file encryption state set during this session so context menus
    // can show only the relevant action (true = encrypted, false = plaintext).
    fileEncryptionCache = new Map<string, boolean>();
    private unlockSession: { closeLeafOnCancel: boolean; leafToClose: WorkspaceLeaf | null } | null = null;
    private unlockFallbackModal: Modal | null = null;
    private unlockEventRefs: EventRef[] = [];
    unlockSuppressNextModalOnClose = false;

    t = (x: TransItemType, vars?: Record<string, string>) => this.i18n.t(x, vars);

    // True when saved data uses the legacy v1 cipher rather than a v2 PBKDF2 hash.
    get isLegacyPassword(): boolean {
        return this.settings.password !== '' && this.settings.passwordData === null;
    }

    async setEncryptionKeyFromPassword(password: string): Promise<void> {
        if (!this.settings.passwordData) return;
        const salt = base64ToBuf(this.settings.passwordData.salt);
        this.encryptionKey = await deriveEncryptionKey(password, salt);
    }

    clearEncryptionKey(): void {
        if (this.encryptionKey) this.encryptionKey.fill(0);
        this.encryptionKey = null;
    }

    updateStatusBar(): void {
        if (!this.statusBarItem) return;
        if (!this.settings.protectEnabled) {
            this.statusBarItem.style.display = 'none';
            return;
        }
        this.statusBarItem.style.display = '';
        this.statusBarItem.setText(
            this.isVerifyPasswordCorrect
                ? this.t('status_bar_unlocked')
                : this.t('status_bar_locked')
        );
    }

    async bulkFolderOp(phase: 'encrypt' | 'decrypt', folderPath: string): Promise<void> {
        if (!this.encryptionKey || !this.vaultPatchHandle) {
            new Notice(this.t('notice_unlock_first'));
            return;
        }
        const title = this.t(phase === 'encrypt' ? 'bulk_encrypt_button' : 'bulk_decrypt_button');
        const runner = phase === 'encrypt' ? encryptFolder : decryptFolder;
        await runBulkWithProgressModal(
            this.app,
            this,
            title,
            (signal, onProgress) =>
                runner(
                    this.app,
                    folderPath,
                    this.encryptionKey as Uint8Array,
                    this.vaultPatchHandle as VaultPatchHandle,
                    onProgress,
                    signal
                )
        );
    }

    confirmBulkFolderOp(phase: 'encrypt' | 'decrypt', folderPath: string, count: number): void {
        const titleKey = phase === 'encrypt' ? 'bulk_encrypt_confirm_title' : 'bulk_decrypt_confirm_title';
        const bodyKey = phase === 'encrypt' ? 'bulk_encrypt_confirm_body' : 'bulk_decrypt_confirm_body';
        const btnKey = phase === 'encrypt' ? 'bulk_encrypt_button' : 'bulk_decrypt_button';
        new BulkConfirmModal(this.app, this, {
            title: this.t(titleKey, { count: String(count) }),
            body: this.t(bodyKey, { folder: folderPath }),
            confirmText: this.t(btnKey),
            onConfirm: () => void this.bulkFolderOp(phase, folderPath),
        }).open();
    }

    requireEncryptionKey(): Uint8Array {
        if (!this.encryptionKey) {
            throw new Error('Vault is locked: encryption key is not loaded.');
        }
        return this.encryptionKey;
    }

    async onload() {
        await this.loadSettings();

        this.lastUnlockOrOpenFileTime = moment();

        this.i18n = new I18n(this.settings.lang, async (lang: LangTypeAndAuto) => {
            this.settings.lang = lang;
            await this.saveSettings();
        });

        // Install vault read/write interception before any other listeners
        // so the very first file-open routes through the encryption wrappers.
        this.vaultPatchHandle = installVaultPatches(this);

        this.passwordRibbonBtn = this.addRibbonIcon(
            'lock',
            this.t('open_password_protection'),
            () => this.openPasswordProtection()
        );

        const statusBarItem = this.addStatusBarItem();
        statusBarItem.addClass('pw-status-bar-item');
        statusBarItem.style.display = 'none';
        statusBarItem.addEventListener('click', () => {
            if (!this.settings.protectEnabled) return;
            if (this.isVerifyPasswordCorrect) {
                void this.openPasswordProtection();
            } else {
                this.verifyPasswordProtection(false);
            }
        });
        this.statusBarItem = statusBarItem;
        this.updateStatusBar();

        this.addCommand({
            id: 'open-password-protection',
            name: this.t('open'),
            callback: () => this.enablePasswordProtection(),
        });

        this.addSettingTab(new PasswordSettingTab(this.app, this));

        this.app.workspace.onLayoutReady(() => {
            if (this.settings.protectEnabled && this.isIncludeRootPath()) {
                if (!this.isVerifyPasswordCorrect) {
                    this.verifyPasswordProtection(false);
                }
            }
        });

        this.registerEvent(
            this.app.workspace.on('file-open', (file: TFile | null) => {
                if (!file) return;
                this.autoLockCheck();
                if (
                    this.settings.protectEnabled &&
                    !this.isVerifyPasswordCorrect &&
                    this.isProtectedFile(file.path)
                ) {
                    this.verifyPasswordProtection(false);
                }
                if (this.settings.protectEnabled && this.isVerifyPasswordCorrect) {
                    this.lastUnlockOrOpenFileTime = moment();
                }
            })
        );

        this.registerEvent(
            this.app.workspace.on('active-leaf-change', (leaf: WorkspaceLeaf | null) => {
                if (!leaf) return;
                this.autoLockCheck();

                const viewType = leaf.view.getViewType();

                // Any file-based view (markdown, canvas, image, pdf, audio, video, …).
                if (leaf.view instanceof FileView && leaf.view.file) {
                    if (
                        this.settings.protectEnabled &&
                        !this.isVerifyPasswordCorrect &&
                        this.isProtectedFile(leaf.view.file.path)
                    ) {
                        this.verifyPasswordProtection(false);
                        return;
                    }
                }

                // Aggregate views that can surface excerpts from protected notes.
                if (AGGREGATE_VIEW_TYPES.has(viewType)) {
                    if (this.settings.protectEnabled && !this.isVerifyPasswordCorrect) {
                        this.verifyPasswordProtection(true, leaf);
                        return;
                    }
                }

                if (this.settings.protectEnabled && this.isVerifyPasswordCorrect) {
                    this.lastUnlockOrOpenFileTime = moment();
                }
            })
        );

        this.registerEvent(this.app.vault.on('rename', this.handleRename));
        this.registerEvent(this.app.vault.on('modify', this.handleFileModify));

        // Redact ![[protected-file]] embeds in reading-mode renders.
        this.registerMarkdownPostProcessor((el, ctx) => {
            if (!this.settings.protectEnabled || this.isVerifyPasswordCorrect) return;

            const embeds = el.querySelectorAll<HTMLElement>('.internal-embed');
            embeds.forEach((embed) => {
                const src = embed.getAttribute('src') ?? '';
                const file = this.app.metadataCache.getFirstLinkpathDest(
                    src,
                    ctx.sourcePath
                );
                if (file && this.isProtectedFile(file.path)) {
                    const shield = new EmbedShield(embed, file.basename, this);
                    ctx.addChild(shield);
                }
            });
        });

        // Context menus: file, folder, multi-select, and editor.
        this.registerEvent(
            this.app.workspace.on('file-menu', (menu: Menu, file: TAbstractFile) => {
                // ── Folder ──────────────────────────────────────────────
                if (file instanceof TFolder) {
                    const folderPath = file.isRoot() ? ROOT_PATH : file.path;
                    const alreadyProtected = this.settings.paths.some(e => e.path === folderPath);
                    const pathEntry = this.settings.paths.find(e => e.path === folderPath);
                    const unlocked = this.settings.protectEnabled && this.isVerifyPasswordCorrect;

                    if (this.settings.protectEnabled && !alreadyProtected) {
                        menu.addItem((item) =>
                            item
                                .setTitle(this.t('folder_menu_protect'))
                                .setIcon('shield')
                                .onClick(async () => {
                                    this.settings.paths.push({ path: folderPath, mode: 'session' });
                                    await this.saveSettings();
                                })
                        );
                    }

                    if (unlocked && pathEntry?.mode === 'encrypted') {
                        menu.addItem((item) =>
                            item
                                .setTitle(this.t('folder_menu_encrypt_all'))
                                .setIcon('lock')
                                .onClick(() => void (async () => {
                                    const counts = await countEncryptedInFolder(
                                        this.app, folderPath, this.vaultPatchHandle!
                                    );
                                    const remaining = counts.total - counts.encrypted;
                                    if (remaining > 0) this.confirmBulkFolderOp('encrypt', folderPath, remaining);
                                })())
                        );
                        menu.addItem((item) =>
                            item
                                .setTitle(this.t('folder_menu_decrypt_all'))
                                .setIcon('unlock')
                                .onClick(() => void (async () => {
                                    const counts = await countEncryptedInFolder(
                                        this.app, folderPath, this.vaultPatchHandle!
                                    );
                                    if (counts.encrypted > 0) this.confirmBulkFolderOp('decrypt', folderPath, counts.encrypted);
                                })())
                        );
                        menu.addItem((item) =>
                            item
                                .setTitle(this.t('folder_menu_set_session'))
                                .setIcon('eye')
                                .onClick(async () => {
                                    const idx = this.settings.paths.findIndex(e => e.path === folderPath);
                                    if (idx >= 0) {
                                        this.settings.paths[idx] = { ...this.settings.paths[idx], mode: 'session' };
                                        await this.saveSettings();
                                    }
                                })
                        );
                    }
                    return;
                }

                // ── Single .md file ──────────────────────────────────────
                if (!(file instanceof TFile) || file.extension !== 'md') return;

                if (this.settings.protectEnabled && !this.isProtectedFile(file.path)) {
                    menu.addItem((item) =>
                        item
                            .setTitle(this.t('file_menu_add_protection'))
                            .setIcon('shield')
                            .onClick(async () => {
                                this.settings.paths.push({ path: file.path, mode: 'session' });
                                await this.saveSettings();
                            })
                    );
                }

                if (!this.settings.protectEnabled || !this.isVerifyPasswordCorrect) return;
                const knownState = this.fileEncryptionCache.get(file.path);
                if (knownState !== true) {
                    menu.addItem((item) =>
                        item
                            .setTitle(this.t('menu_encrypt_file'))
                            .setIcon('lock')
                            .onClick(() => void this.encryptCurrentFile(file))
                    );
                }
                if (knownState !== false) {
                    menu.addItem((item) =>
                        item
                            .setTitle(this.t('menu_decrypt_file'))
                            .setIcon('unlock')
                            .onClick(() => void this.decryptCurrentFile(file))
                    );
                }
            })
        );

        this.registerEvent(
            this.app.workspace.on('files-menu', (menu: Menu, files: TAbstractFile[]) => {
                if (!this.settings.protectEnabled || !this.isVerifyPasswordCorrect) return;
                const mdFiles = files.filter(
                    (f): f is TFile => f instanceof TFile && f.extension === 'md'
                );
                if (mdFiles.length === 0) return;
                menu.addItem((item) =>
                    item
                        .setTitle(this.t('multi_menu_encrypt'))
                        .setIcon('lock')
                        .onClick(() => {
                            for (const f of mdFiles) void this.encryptCurrentFile(f);
                        })
                );
                menu.addItem((item) =>
                    item
                        .setTitle(this.t('multi_menu_decrypt'))
                        .setIcon('unlock')
                        .onClick(() => {
                            for (const f of mdFiles) void this.decryptCurrentFile(f);
                        })
                );
            })
        );

        this.registerEvent(
            this.app.workspace.on('editor-menu', (menu: Menu, _editor, info) => {
                if (!(info instanceof MarkdownView) || !info.file) return;
                if (!this.settings.protectEnabled || !this.isVerifyPasswordCorrect) return;
                if (info.file.extension !== 'md') return;
                const knownState = this.fileEncryptionCache.get(info.file.path);
                if (knownState !== true) {
                    menu.addItem((item) =>
                        item
                            .setTitle(this.t('menu_encrypt_file'))
                            .setIcon('lock')
                            .onClick(() => void this.encryptCurrentFile(info.file!))
                    );
                }
                if (knownState !== false) {
                    menu.addItem((item) =>
                        item
                            .setTitle(this.t('menu_decrypt_file'))
                            .setIcon('unlock')
                            .onClick(() => void this.decryptCurrentFile(info.file!))
                    );
                }
            })
        );

        this.addCommand({
            id: 'encrypt-current-file',
            name: this.t('command_encrypt_current_file'),
            checkCallback: (checking: boolean) => {
                const file = this.app.workspace.getActiveFile();
                if (!file || file.extension !== 'md') return false;
                if (!this.settings.protectEnabled || !this.isVerifyPasswordCorrect) return false;
                if (!checking) void this.encryptCurrentFile(file);
                return true;
            },
        });

        this.addCommand({
            id: 'decrypt-current-file',
            name: this.t('command_decrypt_current_file'),
            checkCallback: (checking: boolean) => {
                const file = this.app.workspace.getActiveFile();
                if (!file || file.extension !== 'md') return false;
                if (!this.settings.protectEnabled || !this.isVerifyPasswordCorrect) return false;
                if (!checking) void this.decryptCurrentFile(file);
                return true;
            },
        });

        // Check auto-lock every 10 seconds.
        this.registerInterval(window.setInterval(() => this.autoLockCheck(), 10_000));
    }

    async encryptCurrentFile(file: TFile): Promise<void> {
        if (!this.vaultPatchHandle) return;
        if (!this.encryptionKey) {
            new Notice(this.t('notice_unlock_first'));
            return;
        }
        try {
            const r = await encryptSingleFile(file, this.encryptionKey, this.vaultPatchHandle);
            if (r === 'already-encrypted') {
                this.fileEncryptionCache.set(file.path, true);
                new Notice(this.t('notice_already_encrypted', { path: file.path }));
            } else {
                this.fileEncryptionCache.set(file.path, true);
                new Notice(this.t('notice_file_encrypted', { path: file.path }));
                void this.rerenderMarkdownViews();
            }
        } catch (e) {
            console.error('pwprot: encryptCurrentFile failed', e);
            new Notice((e instanceof Error ? e.message : String(e)));
        }
    }

    async decryptCurrentFile(file: TFile): Promise<void> {
        if (!this.vaultPatchHandle) return;
        if (!this.encryptionKey) {
            new Notice(this.t('notice_unlock_first'));
            return;
        }
        try {
            const r = await decryptSingleFile(file, this.encryptionKey, this.vaultPatchHandle);
            if (r === 'already-plaintext') {
                this.fileEncryptionCache.set(file.path, false);
                new Notice(this.t('notice_already_plaintext', { path: file.path }));
            } else {
                this.fileEncryptionCache.set(file.path, false);
                new Notice(this.t('notice_file_decrypted', { path: file.path }));
                void this.rerenderMarkdownViews();
            }
        } catch (e) {
            console.error('pwprot: decryptCurrentFile failed', e);
            new Notice((e instanceof Error ? e.message : String(e)));
        }
    }

    async onunload() {
        // Restore vault originals so plugin reload does not nest wrappers.
        this.vaultPatchHandle?.uninstall();
        this.vaultPatchHandle = null;
        // Zero out the in-memory encryption key. No session state persisted —
        // protection re-locks on every startup.
        this.clearEncryptionKey();
    }

    private handleRename = (file: TAbstractFile, oldPath: string) => {
        if (!(file instanceof TFile)) return;
        if (
            this.settings.protectEnabled &&
            !this.isVerifyPasswordCorrect &&
            (this.isProtectedFile(oldPath) || this.isProtectedFile(file.path))
        ) {
            this.verifyPasswordProtection(false);
        }

        const updated = replaceProtectedPathInEntries(oldPath, file.path, this.settings.paths);
        if (updated) {
            this.settings.paths = updated;
            void this.saveSettings();
        }

        if (this.settings.protectEnabled && this.isVerifyPasswordCorrect) {
            this.lastUnlockOrOpenFileTime = moment();
        }
    };

    private handleFileModify = (_file: TFile) => {
        if (this.settings.protectEnabled && this.isVerifyPasswordCorrect) {
            this.lastUnlockOrOpenFileTime = moment();
        }
    };

    async autoLockCheck() {
        if (
            !this.settings.protectEnabled ||
            !this.isVerifyPasswordCorrect ||
            this.settings.autoLockInterval <= 0
        ) {
            return;
        }
        const elapsed = moment().diff(this.lastUnlockOrOpenFileTime, 'minute');
        if (elapsed >= this.settings.autoLockInterval) {
            this.isVerifyPasswordCorrect = false;
            this.clearEncryptionKey();
            this.updateStatusBar();
            const sensitiveOpen =
                this.isProtectFileOpened() || (await this.isEncryptedFileOpen());
            if (sensitiveOpen) {
                await this.closeAllSensitiveLeaves();
                this.verifyPasswordProtection(false);
            }
        }
    }

    isProtectFileOpened(): boolean {
        let found = false;
        this.app.workspace.iterateAllLeaves((leaf) => {
            if (!found && leaf.view instanceof FileView && leaf.view.file) {
                if (this.isProtectedFile(leaf.view.file.path)) found = true;
            }
        });
        return found;
    }

    // True if any open leaf is showing a markdown file whose on-disk body has
    // the encryption sentinel — independent of whether the file's path is in
    // the configured protected paths. Encryption follows the file.
    async isEncryptedFileOpen(): Promise<boolean> {
        if (!this.vaultPatchHandle) return false;
        const candidates: TFile[] = [];
        this.app.workspace.iterateAllLeaves((leaf) => {
            if (leaf.view instanceof FileView && leaf.view.file) {
                const f = leaf.view.file;
                if (f.extension === 'md') candidates.push(f);
            }
        });
        for (const file of candidates) {
            try {
                const raw = await this.vaultPatchHandle.originalRead(file);
                if (isEncryptedFile(raw)) return true;
            } catch {
                // ignore — file may have been deleted between iteration and read
            }
        }
        return false;
    }

    async closeLeaves() {
        const toClose: WorkspaceLeaf[] = [];
        this.app.workspace.iterateAllLeaves((leaf) => {
            if (leaf.view instanceof FileView && leaf.view.file) {
                if (this.isProtectedFile(leaf.view.file.path)) toClose.push(leaf);
            }
        });
        for (const leaf of toClose) {
            leaf.setViewState({ type: 'empty' });
            leaf.detach();
        }
    }

    // Closes leaves whose file is encrypted-by-sentinel even if the file is
    // not currently inside a protected-path rule (e.g. moved out of an
    // encrypted folder).
    async closeEncryptedLeaves(): Promise<void> {
        if (!this.vaultPatchHandle) return;
        const toClose: WorkspaceLeaf[] = [];
        const reads: { leaf: WorkspaceLeaf; file: TFile }[] = [];
        this.app.workspace.iterateAllLeaves((leaf) => {
            if (leaf.view instanceof FileView && leaf.view.file) {
                const f = leaf.view.file;
                if (f.extension === 'md') reads.push({ leaf, file: f });
            }
        });
        for (const { leaf, file } of reads) {
            try {
                const raw = await this.vaultPatchHandle.originalRead(file);
                if (isEncryptedFile(raw)) toClose.push(leaf);
            } catch {
                // ignore
            }
        }
        for (const leaf of toClose) {
            leaf.setViewState({ type: 'empty' });
            leaf.detach();
        }
    }

    async closeAllSensitiveLeaves(): Promise<void> {
        await this.closeLeaves();
        await this.closeEncryptedLeaves();
    }

    async enablePasswordProtection() {
        if (!this.settings.protectEnabled) {
            new Notice(this.t('notice_set_password'));
        } else if (this.isVerifyPasswordCorrect) {
            this.isVerifyPasswordCorrect = false;
            this.clearEncryptionKey();
            await this.closeAllSensitiveLeaves();
            this.updateStatusBar();
        }
    }

    async openPasswordProtection() {
        if (!this.settings.protectEnabled) {
            new Notice(this.t('notice_set_password'));
            return;
        }
        if (this.isVerifyPasswordCorrect) {
            this.isVerifyPasswordCorrect = false;
            this.clearEncryptionKey();
            await this.closeAllSensitiveLeaves();
        }
        this.verifyPasswordProtection(false);
    }

    verifyPasswordProtection(closeLeafOnCancel: boolean, leafToClose?: WorkspaceLeaf | null) {
        if (this.isVerifyPasswordWaitting) return;
        this.isVerifyPasswordWaitting = true;
        this.isVerifyPasswordCorrect = false;
        this.unlockSession = { closeLeafOnCancel, leafToClose: leafToClose ?? null };
        this.registerUnlockSessionEvents();
        this.rebuildPasswordUnlock('init');
    }

    private registerUnlockSessionEvents() {
        this.clearUnlockEventRefs();
        this.unlockEventRefs.push(
            this.app.workspace.on('active-leaf-change', (leaf) => {
                if (this.isVerifyPasswordWaitting) {
                    this.rebuildPasswordUnlock('active-leaf-change', leaf);
                }
            })
        );
        this.unlockEventRefs.push(
            this.app.workspace.on('file-open', () => {
                if (this.isVerifyPasswordWaitting) {
                    this.rebuildPasswordUnlock('file-open');
                }
            })
        );
        this.unlockEventRefs.push(
            this.app.workspace.on('layout-change', () => {
                if (this.isVerifyPasswordWaitting) {
                    this.rebuildPasswordUnlock('layout');
                }
            })
        );
    }

    private clearUnlockEventRefs() {
        for (const r of this.unlockEventRefs) {
            this.app.workspace.offref(r);
        }
        this.unlockEventRefs = [];
    }

    private clearUnlockHostsInWorkspace() {
        this.app.workspace.iterateAllLeaves((leaf) => {
            const view = leaf.view as { contentEl?: HTMLElement };
            const ce = view?.contentEl;
            if (!ce) return;
            ce.querySelectorAll('.pw-unlock-host').forEach((el) => el.remove());
        });
    }

    private mountPasswordFormInto(host: HTMLElement) {
        host.addClass('pw-leaf-unlock-form');
        createPasswordVerifyForm(host, this, (pw) => {
            this.lastUnlockOrOpenFileTime = moment();
            this.isVerifyPasswordCorrect = true;
            void (async () => {
                await this.setEncryptionKeyFromPassword(pw);
                this.teardownPasswordUnlockSession(true);
            })();
        }).focus();
    }

    private rebuildPasswordUnlock(
        source: 'init' | 'file-open' | 'layout' | 'active-leaf-change',
        activeLeafParam?: WorkspaceLeaf | null
    ) {
        const active =
            source === 'active-leaf-change' && activeLeafParam !== undefined
                ? activeLeafParam
                : this.app.workspace.activeLeaf;

        if (source === 'active-leaf-change' && active) {
            if (!isUnlockContextLeaf(active, this)) {
                this.teardownPasswordUnlockSession(false);
                return;
            }
        }
        if (source === 'active-leaf-change' && !active) {
            return;
        }

        this.clearUnlockHostsInWorkspace();
        if (this.unlockFallbackModal) {
            const m = this.unlockFallbackModal;
            this.unlockFallbackModal = null;
            this.unlockSuppressNextModalOnClose = true;
            m.close();
        }

        let placedForm = false;
        this.app.workspace.iterateAllLeaves((leaf) => {
            if (!(leaf.view instanceof FileView) || !leaf.view.file) return;
            if (!this.isProtectedFile(leaf.view.file.path)) return;
            const host = leaf.view.contentEl.createDiv({ cls: 'pw-unlock-host' });
            if (active && leaf === active && isUnlockContextLeaf(active, this)) {
                this.mountPasswordFormInto(host);
                placedForm = true;
            } else {
                host.addClass('pw-leaf-locked');
                host.createDiv({ cls: 'pw-leaf-overlay-icon' }).setText('🔒');
            }
        });

        if (
            active &&
            isUnlockContextLeaf(active, this) &&
            !placedForm &&
            AGGREGATE_VIEW_TYPES.has(active.view.getViewType())
        ) {
            const ce = (active.view as unknown as { contentEl: HTMLElement }).contentEl;
            const host = ce.createDiv({ cls: 'pw-unlock-host' });
            this.mountPasswordFormInto(host);
            placedForm = true;
        }

        if (!placedForm) {
            const m = new UnlockFallbackModal(this.app, this);
            this.unlockFallbackModal = m;
            m.open();
        }
    }

    teardownPasswordUnlockSession(
        verified: boolean,
        options?: { skipModalClose?: boolean }
    ) {
        if (!this.isVerifyPasswordWaitting) return;
        this.isVerifyPasswordWaitting = false;
        this.clearUnlockHostsInWorkspace();
        this.clearUnlockEventRefs();
        const s = this.unlockSession;
        this.unlockSession = null;
        if (!verified) {
            this.isVerifyPasswordCorrect = false;
        }
        if (this.unlockFallbackModal) {
            const m = this.unlockFallbackModal;
            this.unlockFallbackModal = null;
            if (!options?.skipModalClose) m.close();
        }
        if (!verified && s?.closeLeafOnCancel) {
            (s.leafToClose ?? this.app.workspace.activeLeaf)?.detach();
        }
        this.updateStatusBar();
        if (verified) {
            new Notice(this.t('password_protection_closed'));
            setTimeout(() => void this.rerenderMarkdownViews(), 0);
        } else {
            void this.closeAllSensitiveLeaves();
        }
    }

    async rerenderMarkdownViews() {
        if (!this.vaultPatchHandle) return;

        const leaves: { leaf: WorkspaceLeaf; file: TFile }[] = [];
        this.app.workspace.iterateAllLeaves((leaf) => {
            if (leaf.view.getViewType() !== 'markdown') return;
            const view = leaf.view as MarkdownView;
            if (view.file?.extension === 'md') leaves.push({ leaf, file: view.file });
        });

        for (const { leaf, file } of leaves) {
            try {
                const raw = await this.vaultPatchHandle.originalRead(file);
                if (!isEncryptedFile(raw)) continue;

                // vault.read goes through the patched (now-decrypting) wrapper.
                const plaintext = await this.app.vault.read(file);
                const view = leaf.view as MarkdownView;

                // Push plaintext into the CM6 editor (source / live-preview).
                // leaf.openFile can silently skip a reload when the same file is
                // already loaded in the leaf, leaving ciphertext in the editor.
                if (view.editor) {
                    view.editor.setValue(plaintext);
                }

                // Refresh reading-mode renderer.
                view.previewMode?.rerender(true);
            } catch {
                // file gone or unreadable — leave the leaf as-is
            }
        }
    }

    isIncludeRootPath(): boolean {
        return anyEntryIsRoot(this.settings.paths);
    }

    isProtectedFile(filePath: string): boolean {
        return isProtectedByEntries(filePath, this.settings.paths);
    }

    // Migrate from legacy v1 cipher to PBKDF2 hash after successful verification.
    async migratePassword(plaintext: string) {
        const passwordData = await hashPassword(plaintext);
        this.settings.passwordData = passwordData;
        this.settings.password = '';
        await this.saveSettings();
    }

    async loadSettings() {
        const raw = await this.loadData();
        this.settings = migrateSettings(raw);
    }

    async saveSettings() {
        // `paths` is the v3 source of truth. Recompute the legacy fields
        // (`protectedPath`, `addedProtectedPath`) from it on every save so
        // a downgrade to the v2 plugin still finds the primary path and
        // the first ADD_PATH_MAX added paths.
        mirrorPathsToLegacy(this.settings);
        await this.saveData(this.settings);
    }
}

// ─── Embed shield ────────────────────────────────────────────────────────────

class EmbedShield extends MarkdownRenderChild {
    private observer: MutationObserver | null = null;

    constructor(
        containerEl: HTMLElement,
        private readonly filename: string,
        private readonly plugin: PasswordPlugin
    ) {
        super(containerEl);
    }

    onload() {
        this.shield();
        // Re-shield if Obsidian injects embed content asynchronously.
        this.observer = new MutationObserver(() => {
            if (!this.plugin.isVerifyPasswordCorrect) this.shield();
        });
        this.observer.observe(this.containerEl, { childList: true, subtree: false });
    }

    onunload() {
        this.observer?.disconnect();
    }

    private shield() {
        this.containerEl.empty();
        this.containerEl.addClass('pw-protected-embed');
        this.containerEl.createSpan({ text: this.plugin.t('locked_embed') });
    }
}

// ─── Set password modal ───────────────────────────────────────────────────────

class SetPasswordModal extends Modal {
    private onSubmit: () => void;

    constructor(app: App, private plugin: PasswordPlugin, onSubmit: () => void) {
        super(app);
        this.onSubmit = onSubmit;
    }

    onOpen() {
        const { contentEl } = this;
        contentEl.empty();

        const hints = [
            this.plugin.t('hint_enter_in_both_boxes'),
            this.plugin.t('hint_password_must_match'),
            this.plugin.t('hint_password_length'),
        ];

        contentEl.createEl('h2', { text: this.plugin.t('set_password_title') });

        const pwWrap = contentEl.createDiv({ cls: 'pw-input-row' });
        const pwInputEl = pwWrap.createEl('input', { type: 'password' });
        pwInputEl.placeholder = this.plugin.t('place_holder_enter_password');
        pwInputEl.focus();

        const confirmWrap = contentEl.createDiv({ cls: 'pw-input-row' });
        const pwConfirmEl = confirmWrap.createEl('input', { type: 'password' });
        pwConfirmEl.placeholder = this.plugin.t('confirm_password');

        const messageEl = contentEl.createDiv({ cls: 'pw-message' });
        messageEl.setText(hints[0]);

        const setHint = (color: string, idx: number) => {
            messageEl.style.color = color;
            messageEl.setText(hints[idx]);
        };

        pwInputEl.addEventListener('input', () => setHint('', 0));
        pwConfirmEl.addEventListener('input', () => setHint('', 0));

        pwInputEl.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') pwConfirmEl.focus();
        });
        pwConfirmEl.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') void pwChecker();
        });

        const pwChecker = async () => {
            if (!pwInputEl.value || !pwConfirmEl.value) { setHint('red', 0); return; }
            const pw = pwInputEl.value.normalize('NFC');
            if (pw.length < PASSWORD_LENGTH_MIN || pw.length > PASSWORD_LENGTH_MAX) {
                setHint('red', 2); return;
            }
            if (pw !== pwConfirmEl.value.normalize('NFC')) { setHint('red', 1); return; }

            const passwordData = await hashPassword(pw);
            this.plugin.settings.passwordData = passwordData;
            this.plugin.settings.password = '';
            this.plugin.settings.protectEnabled = true;
            // Derive the key immediately so the user stays unlocked — they just
            // proved they know the password by typing it twice.
            await this.plugin.setEncryptionKeyFromPassword(pw);
            this.plugin.isVerifyPasswordCorrect = true;
            this.plugin.lastUnlockOrOpenFileTime = moment();
            this.close();
        };

        new Setting(contentEl)
            .addButton((btn) =>
                btn.setButtonText(this.plugin.t('ok')).setCta().onClick(() => void pwChecker())
            )
            .addButton((btn) =>
                btn.setButtonText(this.plugin.t('cancel')).onClick(() => this.close())
            );
    }

    onClose() {
        this.contentEl.empty();
        this.onSubmit();
    }
}

// ─── Bulk-op confirmation + progress ──────────────────────────────────────────

interface BulkConfirmOptions {
    title: string;
    body: string;
    confirmText: string;
    cancelText?: string;
    onConfirm: () => void | Promise<void>;
}

class BulkConfirmModal extends Modal {
    constructor(app: App, private plugin: PasswordPlugin, private opts: BulkConfirmOptions) {
        super(app);
    }

    onOpen() {
        const { contentEl } = this;
        contentEl.empty();
        contentEl.createEl('h2', { text: this.opts.title });
        contentEl.createEl('p', { text: this.opts.body });

        new Setting(contentEl)
            .addButton((btn) =>
                btn
                    .setButtonText(this.opts.confirmText)
                    .setCta()
                    .onClick(async () => {
                        this.close();
                        await this.opts.onConfirm();
                    })
            )
            .addButton((btn) =>
                btn
                    .setButtonText(this.opts.cancelText ?? this.plugin.t('cancel'))
                    .onClick(() => this.close())
            );
    }

    onClose() {
        this.contentEl.empty();
    }
}

class BulkProgressModal extends Modal {
    private controller = new AbortController();
    private status: HTMLElement | null = null;
    private progressBar: HTMLProgressElement | null = null;
    private actionBtn: HTMLButtonElement | null = null;
    private result: BulkResult | null = null;

    constructor(
        app: App,
        private plugin: PasswordPlugin,
        private title: string,
        private runner: (
            signal: AbortSignal,
            onProgress: BulkProgressCallback
        ) => Promise<BulkResult>,
        private onResolve: (r: BulkResult) => void
    ) {
        super(app);
    }

    onOpen() {
        const { contentEl } = this;
        contentEl.empty();
        contentEl.createEl('h2', { text: this.title });

        this.progressBar = contentEl.createEl('progress', { cls: 'pw-bulk-progress' });
        this.progressBar.max = 1;
        this.progressBar.value = 0;

        this.status = contentEl.createDiv({ cls: 'pw-bulk-status' });
        this.status.setText('…');

        new Setting(contentEl).addButton((btn) => {
            this.actionBtn = btn.buttonEl;
            btn
                .setButtonText(this.plugin.t('bulk_abort'))
                .onClick(() => {
                    if (!this.result) {
                        this.controller.abort();
                    } else {
                        this.close();
                    }
                });
        });

        void this.run();
    }

    private async run() {
        try {
            const result = await this.runner(this.controller.signal, (p) => {
                this.renderProgress(p);
            });
            this.result = result;
            this.renderResult(result);
        } catch (e) {
            console.error('pwprot: bulk op failed', e);
            const err = e instanceof Error ? e.message : String(e);
            if (this.status) this.status.setText(err);
            this.result = {
                ok: 0,
                skipped: 0,
                failed: [{ path: '*', error: err }],
                aborted: false,
                total: 0,
            };
            if (this.actionBtn) this.actionBtn.setText(this.plugin.t('bulk_close'));
        }
    }

    private renderProgress(p: BulkProgress) {
        if (this.progressBar && p.total > 0) {
            this.progressBar.max = p.total;
            this.progressBar.value = p.processed;
        }
        if (!this.status) return;
        this.status.setText(
            this.plugin.t('bulk_running', {
                processed: String(p.processed),
                total: String(p.total),
                current: p.current,
            })
        );
    }

    private renderResult(r: BulkResult) {
        if (this.progressBar) {
            this.progressBar.max = 1;
            this.progressBar.value = r.aborted ? (r.ok + r.skipped + r.failed.length) / Math.max(r.total, 1) : 1;
            if (r.aborted) this.progressBar.addClass('pw-bulk-progress-aborted');
        }
        if (!this.status) return;
        if (r.aborted) {
            this.status.setText(
                this.plugin.t('bulk_aborted', {
                    processed: String(r.ok + r.skipped + r.failed.length),
                    total: String(r.total),
                })
            );
        } else {
            this.status.setText(
                this.plugin.t('bulk_done', {
                    ok: String(r.ok),
                    skipped: String(r.skipped),
                    failed: String(r.failed.length),
                })
            );
        }
        if (r.failed.length > 0) {
            this.status.createEl('div', {
                text: this.plugin.t('bulk_failures_console_hint'),
                cls: 'pw-bulk-failure-hint',
            });
            for (const f of r.failed) {
                console.error(`pwprot: bulk op failed for ${f.path}: ${f.error}`);
            }
        }
        if (this.actionBtn) this.actionBtn.setText(this.plugin.t('bulk_close'));
    }

    onClose() {
        if (!this.result) {
            this.controller.abort();
            this.result = {
                ok: 0,
                skipped: 0,
                failed: [],
                aborted: true,
                total: 0,
            };
        }
        this.contentEl.empty();
        this.onResolve(this.result);
    }
}

function runBulkWithProgressModal(
    app: App,
    plugin: PasswordPlugin,
    title: string,
    runner: (signal: AbortSignal, onProgress: BulkProgressCallback) => Promise<BulkResult>
): Promise<BulkResult> {
    return new Promise<BulkResult>((resolve) => {
        new BulkProgressModal(app, plugin, title, runner, resolve).open();
    });
}

// ─── Disable-protection guard ─────────────────────────────────────────────────

class DisableProtectionGuardModal extends Modal {
    constructor(
        app: App,
        private plugin: PasswordPlugin,
        private encryptedCount: number,
        private onProceed: () => void | Promise<void>
    ) {
        super(app);
    }

    onOpen() {
        const { contentEl } = this;
        contentEl.empty();
        contentEl.createEl('h2', {
            text: this.plugin.t('disable_guard_title', { count: String(this.encryptedCount) }),
        });
        contentEl.createEl('p', { text: this.plugin.t('disable_guard_body') });

        new Setting(contentEl)
            .addButton((btn) =>
                btn
                    .setButtonText(this.plugin.t('disable_guard_decrypt_and_disable'))
                    .setCta()
                    .onClick(async () => {
                        this.close();
                        await this.onProceed();
                    })
            )
            .addButton((btn) =>
                btn.setButtonText(this.plugin.t('cancel')).onClick(() => this.close())
            );
    }

    onClose() {
        this.contentEl.empty();
    }
}

// ─── Change password modal ────────────────────────────────────────────────────

class ChangePasswordModal extends Modal {
    constructor(app: App, private plugin: PasswordPlugin, private onDone: () => void) {
        super(app);
    }

    onOpen() {
        const { contentEl } = this;
        contentEl.empty();
        contentEl.createEl('h2', { text: this.plugin.t('change_password_title') });

        const oldEl = contentEl.createDiv({ cls: 'pw-input-row' }).createEl('input', {
            type: 'password',
        });
        oldEl.placeholder = this.plugin.t('change_password_old');
        oldEl.focus();

        const newEl = contentEl.createDiv({ cls: 'pw-input-row' }).createEl('input', {
            type: 'password',
        });
        newEl.placeholder = this.plugin.t('change_password_new');

        const confEl = contentEl.createDiv({ cls: 'pw-input-row' }).createEl('input', {
            type: 'password',
        });
        confEl.placeholder = this.plugin.t('change_password_confirm');

        const messageEl = contentEl.createDiv({ cls: 'pw-message' });
        const setMsg = (text: string, color = '') => {
            messageEl.style.color = color;
            messageEl.setText(text);
        };

        const submit = async () => {
            const oldPw = oldEl.value.normalize('NFC');
            const newPw = newEl.value.normalize('NFC');
            const conf = confEl.value.normalize('NFC');

            if (!oldPw || !newPw || !conf) {
                setMsg(this.plugin.t('hint_enter_in_both_boxes'), 'red');
                return;
            }
            if (newPw.length < PASSWORD_LENGTH_MIN || newPw.length > PASSWORD_LENGTH_MAX) {
                setMsg(this.plugin.t('hint_password_length'), 'red');
                return;
            }
            if (newPw !== conf) {
                setMsg(this.plugin.t('hint_password_must_match'), 'red');
                return;
            }
            if (!this.plugin.settings.passwordData) {
                setMsg(this.plugin.t('hint_password_length'), 'red');
                return;
            }
            const ok = await verifyPasswordHash(oldPw, this.plugin.settings.passwordData);
            if (!ok) {
                setMsg(this.plugin.t('change_password_old_wrong'), 'red');
                return;
            }

            this.close();
            await this.runChangePassword(oldPw, newPw);
        };

        oldEl.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') newEl.focus();
        });
        newEl.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') confEl.focus();
        });
        confEl.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') void submit();
        });

        new Setting(contentEl)
            .addButton((btn) =>
                btn
                    .setButtonText(this.plugin.t('ok'))
                    .setCta()
                    .onClick(() => void submit())
            )
            .addButton((btn) =>
                btn.setButtonText(this.plugin.t('cancel')).onClick(() => this.close())
            );
    }

    private async runChangePassword(oldPw: string, newPw: string) {
        if (!this.plugin.settings.passwordData || !this.plugin.vaultPatchHandle) {
            this.onDone();
            return;
        }
        const oldKey = await deriveEncryptionKey(
            oldPw,
            base64ToBuf(this.plugin.settings.passwordData.salt)
        );
        const newPasswordData = await hashPassword(newPw);
        const newKey = await deriveEncryptionKey(newPw, base64ToBuf(newPasswordData.salt));

        const result = await runBulkWithProgressModal(
            this.app,
            this.plugin,
            this.plugin.t('change_password_title'),
            (signal, onProgress) =>
                reencryptAll(
                    this.app,
                    oldKey,
                    newKey,
                    // patches handle is non-null per the guard above
                    this.plugin.vaultPatchHandle as VaultPatchHandle,
                    onProgress,
                    signal
                )
        );

        // Persist the new password data only on success — on partial / aborted
        // runs, keep the old hash so the user can retry. The dual-key fallback
        // in reencryptAll makes a retry resume cleanly.
        if (!result.aborted && result.failed.length === 0) {
            this.plugin.settings.passwordData = newPasswordData;
            this.plugin.encryptionKey = newKey;
            await this.plugin.saveSettings();
            new Notice(this.plugin.t('change_password_done', { ok: String(result.ok) }));
        } else {
            // Roll back the in-memory key to the old one so the user is not
            // left in a state where reads of files still encrypted with the
            // old key fail.
            this.plugin.encryptionKey = oldKey;
        }
        this.onDone();
    }

    onClose() {
        this.contentEl.empty();
    }
}

// ─── Settings tab ─────────────────────────────────────────────────────────────

class PasswordSettingTab extends PluginSettingTab {
    private pathInputSettings: Setting[] = [];

    constructor(app: App, private plugin: PasswordPlugin) {
        super(app, plugin);
    }

    display(): void {
        const { containerEl } = this;
        containerEl.empty();
        this.pathInputSettings = [];

        this.renderEnableToggle(containerEl);

        const locked = this.plugin.settings.protectEnabled;

        const lockSectionEl = containerEl.createDiv({ cls: 'pw-section-header' });
        lockSectionEl.createSpan({ text: this.plugin.t('section_lock_behavior') });
        if (locked) {
            lockSectionEl.createSpan({ cls: 'pw-section-locked-tag', text: this.plugin.t('section_locked_tag') });
        }

        const autolockSetting = new Setting(containerEl)
            .setName(this.plugin.t('auto_lock_interval_name'))
            .setDesc(this.plugin.t('auto_lock_interval_desc'));
        addHelpIcon(
            autolockSetting,
            this.app,
            this.plugin.t('help_autolock_title'),
            this.plugin.t('help_autolock_body'),
            this.plugin.t('help_close')
        );
        autolockSetting
            .addText((text) =>
                text
                    .setPlaceholder('0')
                    .setValue(this.plugin.settings.autoLockInterval.toString())
                    .onChange(async (value) => {
                        const sanitised = value.replace(/[^0-9]/g, '');
                        const interval = sanitised ? parseInt(sanitised) : 0;
                        if (!isNaN(interval) && interval >= 0) {
                            this.plugin.settings.autoLockInterval = interval;
                            await this.plugin.saveSettings();
                        }
                    })
            )
            .setDisabled(locked);

        const hintSetting = new Setting(containerEl)
            .setName(this.plugin.t('setting_pwd_hint_question_name'))
            .setDesc(this.plugin.t('setting_pwd_hint_question_desc'));
        addHelpIcon(
            hintSetting,
            this.app,
            this.plugin.t('help_pwhint_title'),
            this.plugin.t('help_pwhint_body'),
            this.plugin.t('help_close')
        );
        hintSetting
            .addText((text) =>
                text
                    .setPlaceholder(this.plugin.t('place_holder_enter_pwd_hint_question'))
                    .setValue(this.plugin.settings.pwdHintQuestion)
                    .onChange(async (value) => {
                        if (typeof value === 'string' && value.length <= PASSWORD_LENGTH_MAX) {
                            this.plugin.settings.pwdHintQuestion = value;
                            await this.plugin.saveSettings();
                        }
                    })
            )
            .setDisabled(locked);

        if (this.plugin.settings.protectEnabled) {
            const cpSetting = new Setting(containerEl)
                .setName(this.plugin.t('setting_change_password_name'))
                .setDesc(this.plugin.t('setting_change_password_desc'));
            addHelpIcon(
                cpSetting,
                this.app,
                this.plugin.t('help_changepw_title'),
                this.plugin.t('help_changepw_body'),
                this.plugin.t('help_close')
            );
            cpSetting.addButton((btn) =>
                btn
                    .setButtonText(this.plugin.t('change_password_button'))
                    .setDisabled(!this.plugin.isVerifyPasswordCorrect)
                    .onClick(() => {
                        new ChangePasswordModal(this.app, this.plugin, () => this.display()).open();
                    })
            );
        }

        // ─── Protected paths section ────────────────────────────────────
        // Path settings can be edited when protection is off (initial setup)
        // or when protection is on AND the user is currently unlocked. The
        // legacy "edit only when off" pattern would have prevented mode
        // changes during normal use.
        const canEditPaths =
            !this.plugin.settings.protectEnabled || this.plugin.isVerifyPasswordCorrect;

        containerEl.createDiv({ cls: 'pw-section-divider' });

        const pathsSection = new Setting(containerEl)
            .setName(this.plugin.t('protected_paths_section_name'))
            .setDesc(this.plugin.t('protected_paths_section_desc'));
        addHelpIcon(
            pathsSection,
            this.app,
            this.plugin.t('help_paths_title'),
            this.plugin.t('help_paths_body'),
            this.plugin.t('help_close')
        );
        pathsSection.addButton((btn) =>
            btn
                .setButtonText(this.plugin.t('picker_button_label'))
                .setCta()
                .setDisabled(!canEditPaths)
                .onClick(() => this.openPathPicker())
        );

        const pathsList = containerEl.createDiv({ cls: 'pw-paths-list' });
        if (this.plugin.settings.paths.length === 0) {
            pathsList.createDiv({
                cls: 'pw-paths-empty',
                text: this.plugin.t('protected_paths_empty'),
            });
        } else {
            for (let i = 0; i < this.plugin.settings.paths.length; i++) {
                this.buildPathRow(pathsList, i, canEditPaths);
            }
        }
    }

    private openPathPicker() {
        const initial = new Set(
            this.plugin.settings.paths
                .map((e) => (e.path ?? '').trim())
                .filter((p) => p !== '')
        );
        new PathPickerModal(this.app, {
            initialSelected: initial,
            t: (k, v) => this.plugin.t(k, v),
            onConfirm: async (selected) => {
                // Preserve mode for entries that were already in `paths`,
                // default new ones to session mode.
                const oldByPath = new Map<string, ProtectionMode>();
                for (const e of this.plugin.settings.paths) {
                    if (e.path) oldByPath.set(e.path, e.mode);
                }
                const next: ProtectedPathEntry[] = [];
                // Stable order: keep the user's existing ordering for entries
                // they kept; append newly-added entries in path order.
                const seen = new Set<string>();
                for (const e of this.plugin.settings.paths) {
                    if (selected.has(e.path)) {
                        next.push(e);
                        seen.add(e.path);
                    }
                }
                const added = [...selected].filter((p) => !seen.has(p)).sort();
                for (const path of added) {
                    next.push({ path, mode: oldByPath.get(path) ?? 'session' });
                }
                this.plugin.settings.paths = next;
                await this.plugin.saveSettings();
                this.display();
            },
        }).open();
    }

    private pathLabel(path: string): string {
        const item = this.app.vault.getAbstractFileByPath(path);
        if (item instanceof TFolder) return '📁 ' + path;
        if (item instanceof TFile) return '📄 ' + path;
        return path;
    }

    private buildPathRow(
        container: HTMLElement,
        entryIndex: number,
        canEdit: boolean
    ): void {
        const entry = this.plugin.settings.paths[entryIndex];
        if (!entry) return;

        const setting = new Setting(container)
            .setName(entry.path === ROOT_PATH ? this.plugin.t('picker_root_label') : this.pathLabel(entry.path))
            .setClass('pw-path-row')
            .addDropdown((dd) => {
                dd.addOption('session', this.plugin.t('mode_session'));
                dd.addOption('encrypted', this.plugin.t('mode_encrypted'));
                dd.setValue(entry.mode);
                dd.onChange(async (raw: string) => {
                    const newMode: ProtectionMode = raw === 'encrypted' ? 'encrypted' : 'session';
                    const list = this.plugin.settings.paths;
                    if (list[entryIndex]) {
                        list[entryIndex] = { ...list[entryIndex], mode: newMode };
                    }
                    await this.plugin.saveSettings();

                    // Tell the user *why* nothing happened if state blocks the
                    // bulk op (silent early-returns were the original bug).
                    if (!this.plugin.settings.protectEnabled) {
                        new Notice(this.plugin.t('notice_mode_set_protect_off'));
                        void this.refreshPathStatus(entryIndex, statusEl, actionContainer);
                        return;
                    }
                    if (!this.plugin.isVerifyPasswordCorrect || !this.plugin.encryptionKey) {
                        new Notice(this.plugin.t('notice_mode_set_locked'));
                        void this.refreshPathStatus(entryIndex, statusEl, actionContainer);
                        return;
                    }
                    if (!this.plugin.vaultPatchHandle) {
                        new Notice(this.plugin.t('notice_mode_set_no_key'));
                        void this.refreshPathStatus(entryIndex, statusEl, actionContainer);
                        return;
                    }

                    await this.maybeOfferModeFlipBulkOp(entryIndex, newMode);
                    void this.refreshPathStatus(entryIndex, statusEl, actionContainer);
                });
                if (!canEdit) dd.setDisabled(true);
            });

        const statusEl = setting.controlEl.createDiv({ cls: 'pw-path-status' });
        statusEl.setText(this.plugin.t('path_status_loading'));
        const actionContainer = setting.controlEl.createDiv({ cls: 'pw-path-action' });

        if (canEdit) {
            const removeBtn = setting.controlEl.createEl('button', {
                cls: 'pw-path-remove',
                text: '✕',
                attr: { 'aria-label': this.plugin.t('protected_paths_remove_tooltip') },
            });
            removeBtn.title = this.plugin.t('protected_paths_remove_tooltip');
            removeBtn.onclick = async () => {
                this.plugin.settings.paths.splice(entryIndex, 1);
                await this.plugin.saveSettings();
                this.display();
            };
        }

        this.pathInputSettings.push(setting);
        void this.refreshPathStatus(entryIndex, statusEl, actionContainer);
    }

    private async refreshPathStatus(
        pathIndex: number,
        statusEl: HTMLElement,
        actionEl: HTMLElement
    ): Promise<void> {
        actionEl.empty();
        if (!this.plugin.vaultPatchHandle) {
            statusEl.empty();
            return;
        }
        const folderPath = this.plugin.settings.paths[pathIndex]?.path ?? '';
        if (!folderPath || folderPath.trim() === '') {
            statusEl.empty();
            return;
        }
        let counts: { total: number; encrypted: number };
        try {
            counts = await countEncryptedInFolder(
                this.app,
                folderPath,
                this.plugin.vaultPatchHandle
            );
        } catch (e) {
            statusEl.setText('');
            console.error('pwprot: count failed', e);
            return;
        }
        statusEl.setText(
            this.plugin.t('path_status_encrypted_count', {
                encrypted: String(counts.encrypted),
                total: String(counts.total),
            })
        );

        const mode = this.plugin.settings.paths[pathIndex]?.mode ?? 'session';
        const canRunBulk =
            this.plugin.settings.protectEnabled && this.plugin.isVerifyPasswordCorrect;

        // When locked: show a subtle "Unlock to encrypt/decrypt" hint so the
        // user knows the action is available once they unlock.
        if (!canRunBulk && this.plugin.settings.protectEnabled) {
            const needsEncrypt = mode === 'encrypted' && counts.encrypted < counts.total && counts.total > 0;
            const needsDecrypt = mode === 'session' && counts.encrypted > 0;
            if (needsEncrypt || needsDecrypt) {
                const hint = actionEl.createEl('span', { cls: 'pw-path-locked-hint' });
                hint.setText(needsEncrypt
                    ? this.plugin.t('path_action_unlock_to_encrypt')
                    : this.plugin.t('path_action_unlock_to_decrypt'));
            }
            return;
        }
        if (!canRunBulk) return;

        // Show "Encrypt all" if mode is encrypted but some files are still
        // plaintext. Show "Decrypt all" if mode is session but some files are
        // still encrypted.
        if (mode === 'encrypted' && counts.encrypted < counts.total && counts.total > 0) {
            const btn = actionEl.createEl('button', {
                text: this.plugin.t('bulk_encrypt_button'),
            });
            btn.onclick = () =>
                this.runEncryptFolderUI(folderPath, counts.total - counts.encrypted);
        } else if (mode === 'session' && counts.encrypted > 0) {
            const btn = actionEl.createEl('button', {
                text: this.plugin.t('bulk_decrypt_button'),
            });
            btn.onclick = () => this.runDecryptFolderUI(folderPath, counts.encrypted);
        }
    }

    private async maybeOfferModeFlipBulkOp(
        pathIndex: number,
        newMode: ProtectionMode
    ): Promise<void> {
        if (!this.plugin.settings.protectEnabled || !this.plugin.isVerifyPasswordCorrect) return;
        if (!this.plugin.vaultPatchHandle) return;
        const folderPath = this.plugin.settings.paths[pathIndex]?.path ?? '';
        if (!folderPath) return;
        const counts = await countEncryptedInFolder(
            this.app,
            folderPath,
            this.plugin.vaultPatchHandle
        );

        if (newMode === 'encrypted') {
            const remaining = counts.total - counts.encrypted;
            if (remaining <= 0) return;
            new BulkConfirmModal(this.app, this.plugin, {
                title: this.plugin.t('mode_flip_to_encrypted_title'),
                body: this.plugin.t('mode_flip_to_encrypted_body', {
                    folder: folderPath,
                    count: String(remaining),
                }),
                confirmText: this.plugin.t('mode_flip_yes_now'),
                cancelText: this.plugin.t('mode_flip_later'),
                onConfirm: () => this.runFolderBulk('encrypt', folderPath),
            }).open();
        } else {
            if (counts.encrypted <= 0) return;
            new BulkConfirmModal(this.app, this.plugin, {
                title: this.plugin.t('mode_flip_to_session_title'),
                body: this.plugin.t('mode_flip_to_session_body', {
                    folder: folderPath,
                    count: String(counts.encrypted),
                }),
                confirmText: this.plugin.t('mode_flip_yes_now'),
                cancelText: this.plugin.t('mode_flip_later'),
                onConfirm: () => this.runFolderBulk('decrypt', folderPath),
            }).open();
        }
    }

    // One-shot bulk op: progress modal, no extra confirm. Used both from the
    // mode-flip confirm and from per-row "Encrypt all"/"Decrypt all" buttons
    // (the per-row buttons add their own confirm before calling this).
    private async runFolderBulk(
        phase: 'encrypt' | 'decrypt',
        folderPath: string
    ): Promise<void> {
        if (!this.plugin.encryptionKey || !this.plugin.vaultPatchHandle) {
            new Notice(this.plugin.t('notice_unlock_first'));
            return;
        }
        const title = this.plugin.t(
            phase === 'encrypt' ? 'bulk_encrypt_button' : 'bulk_decrypt_button'
        );
        const runner = phase === 'encrypt' ? encryptFolder : decryptFolder;
        const result = await runBulkWithProgressModal(
            this.app,
            this.plugin,
            title,
            (signal, onProgress) =>
                runner(
                    this.app,
                    folderPath,
                    this.plugin.encryptionKey as Uint8Array,
                    this.plugin.vaultPatchHandle as VaultPatchHandle,
                    onProgress,
                    signal
                )
        );
        if (!result.aborted && result.failed.length === 0 && result.ok > 0) {
            new Notice(
                this.plugin.t('bulk_done', {
                    ok: String(result.ok),
                    skipped: String(result.skipped),
                    failed: '0',
                })
            );
        }
        this.display();
    }

    private runEncryptFolderUI(folderPath: string, count: number) {
        new BulkConfirmModal(this.app, this.plugin, {
            title: this.plugin.t('bulk_encrypt_confirm_title', { count: String(count) }),
            body: this.plugin.t('bulk_encrypt_confirm_body', { folder: folderPath }),
            confirmText: this.plugin.t('bulk_encrypt_button'),
            onConfirm: () => this.runFolderBulk('encrypt', folderPath),
        }).open();
    }

    private runDecryptFolderUI(folderPath: string, count: number) {
        new BulkConfirmModal(this.app, this.plugin, {
            title: this.plugin.t('bulk_decrypt_confirm_title', { count: String(count) }),
            body: this.plugin.t('bulk_decrypt_confirm_body', { folder: folderPath }),
            confirmText: this.plugin.t('bulk_decrypt_button'),
            onConfirm: () => this.runFolderBulk('decrypt', folderPath),
        }).open();
    }

    private renderEnableToggle(containerEl: HTMLElement) {
        const setting = new Setting(containerEl)
            .setName(this.plugin.t('setting_toggle_name'))
            .setDesc(this.plugin.t('setting_toggle_desc'));
        addHelpIcon(
            setting,
            this.app,
            this.plugin.t('help_toggle_title'),
            this.plugin.t('help_toggle_body'),
            this.plugin.t('help_close')
        );
        setting.addToggle((toggle) =>
                toggle
                    .setValue(this.plugin.settings.protectEnabled)
                    .onChange((value) => {
                        if (value) {
                            this.plugin.settings.protectEnabled = false;
                            new SetPasswordModal(this.app, this.plugin, () => {
                                if (this.plugin.settings.protectEnabled) {
                                    // User stays unlocked — key was derived inside SetPasswordModal.
                                    void this.plugin.saveSettings();
                                    this.plugin.updateStatusBar();
                                }
                                this.display();
                            }).open();
                        } else {
                            if (!this.plugin.isVerifyPasswordWaitting) {
                                new SettingsPasswordModal(this.app, this.plugin, () => {
                                    if (this.plugin.isVerifyPasswordCorrect) {
                                        void this.handleDisableProtection();
                                    } else {
                                        this.display();
                                    }
                                }).open();
                            }
                        }
                    })
            );
    }

    private async handleDisableProtection(): Promise<void> {
        if (!this.plugin.vaultPatchHandle) {
            this.applyDisable();
            return;
        }
        const counts = await countEncryptedVaultWide(this.app, this.plugin.vaultPatchHandle);
        if (counts.encrypted === 0) {
            this.applyDisable();
            return;
        }
        new DisableProtectionGuardModal(
            this.app,
            this.plugin,
            counts.encrypted,
            async () => {
                if (!this.plugin.encryptionKey || !this.plugin.vaultPatchHandle) {
                    new Notice(this.plugin.t('notice_unlock_first'));
                    this.display();
                    return;
                }
                const result = await runBulkWithProgressModal(
                    this.app,
                    this.plugin,
                    this.plugin.t('disable_guard_decrypt_and_disable'),
                    (signal, onProgress) =>
                        decryptFolder(
                            this.app,
                            ROOT_PATH,
                            this.plugin.encryptionKey as Uint8Array,
                            this.plugin.vaultPatchHandle as VaultPatchHandle,
                            onProgress,
                            signal
                        )
                );
                if (!result.aborted && result.failed.length === 0) {
                    this.applyDisable();
                } else {
                    // Abort or per-file failure: keep protection on so user can retry.
                    this.display();
                }
            }
        ).open();
        // The modal owns the rest of the flow; if the user cancels, redisplay.
        // (The modal calls onProceed only on confirm; cancel just closes.)
    }

    private applyDisable() {
        this.plugin.settings.protectEnabled = false;
        this.plugin.isVerifyPasswordCorrect = false;
        this.plugin.clearEncryptionKey();
        void this.plugin.saveSettings();
        void this.plugin.closeAllSensitiveLeaves();
        this.plugin.updateStatusBar();
        this.display();
    }
}
