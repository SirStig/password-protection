English | [中文](#中文版说明)

---

# Noteguard

> Obsidian plugin: lock notes and folders with a password, with optional real at-rest AES-GCM encryption per path.
>
> Fork of [`qing3962/password-protection`](https://github.com/qing3962/password-protection) with the encryption pipeline, bulk operations, and change-password rekey added.

Choose **Session mode** for a cheap UI lock or **Encrypted mode** for real at-rest AES-GCM encryption — set per-path, mix and match.

## What it does

- Password-gates any folder or individual note path inside your vault, with two modes per path:
  - **Session mode**: files stay plaintext on disk; the plugin only locks the Obsidian UI. Search and graph still work while locked. Cheap, no data-loss risk.
  - **Encrypted mode**: files are written as AES-GCM ciphertext on disk inside a clearly-marked sentinel block. Decryption happens transparently while the vault is unlocked.
- Blurs the workspace and prompts for a password when a protected note is about to open.
- Redacts `![[embedded]]` transclusions of protected files in reading mode.
- Auto-locks after a configurable idle interval; the in-memory encryption key is zeroed on every lock.
- Blocks search, backlinks, and outgoing-link panes until unlocked when protection is active.
- Bulk encrypt or decrypt every Markdown file under any protected path, with progress and a resumable (per-file) commit model.
- Per-file **Encrypt this file** / **Decrypt this file** commands and right-click items.
- Change-password flow re-encrypts every encrypted file with the new password (idempotent across crashes).
- Password stored as a PBKDF2 + SHA-256 hash with a random 16-byte salt; the encryption key is HMAC-derived from the same PBKDF2 output via a separate domain so the on-disk verification hash and the in-memory encryption key are different bytes.

## Encrypted mode

Each protected path has a **mode** dropdown: `Session` or `Encrypted`. The mode dictates the *default for new files* added to that folder. Encryption status of an *existing* file lives in its on-disk sentinel header — so a file moved out of an encrypted folder stays encrypted until you explicitly decrypt it.

An encrypted Markdown file looks like this on disk:

```
> [!warning] Password Protection — encrypted note
> This file is encrypted by the **Password Protection** Obsidian plugin.
> Do not edit it in another editor or it will become unreadable.
> Open it in Obsidian and unlock to view its contents.

```pwprot-v1
<base64 envelope: salt + iv + AES-GCM ciphertext>
```
```

Each save uses a fresh random IV; tampering or wrong-password decryption attempts surface as `auth-failed` and the file is left untouched.

### Honest limits of encrypted mode

- **Lost password = lost data.** There is no backdoor by design.
- **Search / quick-switcher / backlinks do not match plaintext** of encrypted files, even when unlocked. Obsidian's metadata cache is built from on-disk bytes; the public API has no hook for injecting decrypted text into the cache.
- **Sync diffs are noisy.** Every save changes the IV, so every byte of the envelope changes — Obsidian Sync sees a fresh write each time.
- **Files moved into an encrypted folder are not retroactively encrypted.** Use right-click → Encrypt this file (or settings → Encrypt all) to opt them in.

## Security model and honest limitations

**Session mode** protects against casual access inside the Obsidian UI on the device where the plugin is running — e.g. someone picking up your phone or sitting at your desk while Obsidian is open. It does *not* protect note bytes from anyone with file-system access.

**Encrypted mode** protects note bytes at rest:

| Vector | Session mode | Encrypted mode |
|--------|--------------|----------------|
| Reading `.md` files directly via a file manager, terminal, or another editor | Not protected | Protected — files are AES-GCM ciphertext |
| Obsidian Sync to another device / cloud copy | Note content visible to anyone with file access | Note content is ciphertext until unlocked on a device with the same password |
| Graph view node titles | File names visible | File names visible (plaintext on disk) |
| Hover preview popups (within Obsidian) | May briefly show content before the guard fires | Show ciphertext / decrypted text per current lock state |
| Lost password recovery | Possible — files are plaintext | **Impossible** — no backdoor |

## Upgrading from v1.x

Your existing password is automatically migrated to the new secure hash format the first time you enter it after upgrading. You do not need to reset your password.

## Settings

| Setting | Description |
|---------|-------------|
| Enable/Disable password protection | Toggle protection on (sets a new password) or off (requires current password and decryption of any encrypted files). |
| Auto-lock | Minutes of inactivity before the vault re-locks. `0` disables auto-lock. |
| Password prompt | An optional hint question shown when the password is wrong. |
| Change password | Re-encrypts every encrypted file with the new password. Idempotent across crashes (re-run with the same new password to resume). |
| Protected folder or file | Primary path to protect. Default `/` protects the entire vault. Pick **Session** or **Encrypted** mode per path. |
| More folders or files | Up to 6 additional paths, each with its own mode. |
| Encrypt all / Decrypt all | Per-row bulk button to convert every existing file under that path to/from ciphertext. |

## Usage

1. Open **Settings → Password Protection** and set a path and password.
2. Enable protection with the toggle.
3. The lock icon in the ribbon manually re-locks the vault.
4. Use the **Lock** command from the command palette to lock at any time.

## Known bypass vectors (best-effort mitigations)

- **Graph view** — file names are visible as graph nodes. Clicking a node fires the password prompt before the note opens.
- **Drag-and-drop** — dropping a protected file into the editor triggers the same `file-open` handler as a normal click and will prompt for the password. An extremely rapid drop before the event fires could briefly show content; the guard closes the leaf immediately after.
- **Hover previews** — Obsidian renders link-hover popups outside the standard markdown pipeline. This is a known gap; avoid hovering over links to protected files while locked.
- **Quick Switcher / file URI** — `file-open` fires for all these entry points; protection applies.

## Installation

Install from the Obsidian Community Plugin browser, or manually:

1. Download the latest release zip and unzip it into `.obsidian/plugins/password-protection/`.
2. The folder should contain `main.js`, `manifest.json`, and `styles.css`.
3. Restart Obsidian, go to Settings → Community Plugins, and enable **Password Protection**.

## Contributing

Bug reports and pull requests are welcome at the [GitHub repository](https://github.com/qing3962/password-protection/issues).

To add a new language, copy `langs/en.json`, translate the values, and submit a PR.

## Changelog

### v3.0.0

- **Rebrand**: Renamed from "Password Protection" to **Noteguard**. Plugin id changed to `noteguard`.
- **Feature**: Per-path **Encrypted mode** — files are written as AES-GCM ciphertext on disk (sentinel-marked Markdown), transparently decrypted on read while unlocked. Lost password = lost data, by design.
- **Feature**: Bulk encrypt / decrypt for any protected folder, with progress, abort, and per-file resumable commits.
- **Feature**: Right-click → **Encrypt this file** / **Decrypt this file** plus matching command-palette commands.
- **Feature**: Change-password flow re-encrypts every encrypted file with the new password; idempotent if interrupted (re-run with the same new password).
- **Feature**: Disable-protection guard — toggling protection off while encrypted files exist now requires decrypting them first, preventing accidental lockout.
- **Security**: AES-GCM keys are HMAC-derived from PBKDF2 output via a separate domain, so the verification hash on disk and the encryption key in memory are different bytes — neither is computable from the other without the password.
- **Settings**: New v3 schema (`paths` array with per-entry mode); existing v2 settings migrate automatically with all paths in `session` mode.
- **i18n**: Added 30+ new strings for the encryption UI (English; other locales fall back automatically).

### v2.0.0

- **Security**: Removed hardcoded master bypass password (`SOLID_PASS`).
- **Security**: Password storage replaced with PBKDF2/SHA-256 (200,000 iterations, random 16-byte salt). Old passwords migrate automatically on first login.
- **Security**: Removed the 2-second "same restart" session carry-over that allowed bypassing the lock after a quick restart.
- **Fix**: Extra protected paths were silently ignored if more than 6 were saved — now correctly truncated.
- **Fix**: Embed redaction — `![[protected-note]]` transclusions are now replaced with a locked placeholder in reading mode; Obsidian's async embed loader is watched and re-shielded.
- **Fix**: Broader workspace coverage — `active-leaf-change` now guards all `FileView` subtypes (canvas, PDF, image, audio, video) in addition to markdown notes, plus search, backlinks, and outgoing-link panes.
- **Fix**: When cancelling the password modal on a protected aggregate view (search, etc.), that leaf is now closed rather than re-opening the modal in an infinite loop.
- **Fix**: Re-renders open markdown views after a successful unlock so embedded content appears without requiring navigation away and back.
- **Tooling**: Updated to TypeScript 5.5, esbuild 0.25, Node types 22; `minAppVersion` set to 1.4.0.

### v1.1.27 (2025-01-01)
Support for multiple protected paths and individual file path protection.

### v1.1.12 (2023-08-16)
Auto-lock interval setting.

## Credits

Based on [`qing3962/password-protection`](https://github.com/qing3962/password-protection) (MIT). The original session-lock plumbing, embed redaction, and i18n scaffolding are upstream; the Noteguard fork adds the encryption pipeline, vault read/write interception, bulk operations, and change-password rekey.

## License

[MIT License](LICENSE) — original copyright Qing Li (2023), fork copyright SirStig (2026).

---

# 中文版说明

## 用途

本插件不加密、不解密笔记，仅通过密码锁定 Obsidian 界面，防止他人在 Obsidian 中查看私人笔记。

## 安全模型说明

本插件**只保护 Obsidian 界面内**的访问行为，例如防止他人拿起你的手机或在你的桌面前打开受保护的笔记。

**以下情况不受保护：**
- 通过文件管理器、终端或其他编辑器直接读取 `.md` 文件（文件以明文存储在磁盘）
- Obsidian Sync — 笔记文件照常同步，在其他已同步设备上以明文存在；插件设置（含密码哈希）也会同步，因此同一密码可在所有设备上使用
- 图谱视图中的文件名仍然可见
- 悬停预览弹窗可能短暂显示受保护笔记的内容

## 从 v1.x 升级

首次升级后输入旧密码时，密码将自动迁移到新的安全存储格式，无需重置密码。

## 安装、配置和使用

1. 从社区插件市场安装，或手动将 `main.js`、`manifest.json`、`styles.css` 放入 `.obsidian/plugins/password-protection/`；
2. 在设置页设置要保护的路径和密码，启用密码保护开关；
3. 左侧栏的锁形图标可随时手动锁定保险库；
4. 命令面板中也有"Lock"命令可用。

## 许可证

[MIT License](LICENSE)
