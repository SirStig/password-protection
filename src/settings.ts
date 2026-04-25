import type { LangTypeAndAuto } from '../i18n';
import type { PasswordData } from './crypto';
import { ROOT_PATH, ADD_PATH_MAX, ProtectedPathEntry } from './path-utils';

export const SETTINGS_VERSION = 3 as const;

export interface PasswordPluginSettings {
    // Legacy fields (v2). Source of truth in Phase 1; mirrored from `paths` in
    // Phase 3 once the settings UI writes to `paths` directly.
    protectedPath: string;
    addedProtectedPath: string[];
    protectEnabled: boolean;
    // Legacy v1 cipher — cleared after migration to v2 PBKDF2 hash.
    password: string;
    // v2 PBKDF2 hash + salt.
    passwordData: PasswordData | null;
    lang: LangTypeAndAuto;
    autoLockInterval: number;
    pwdHintQuestion: string;

    // v3: per-path mode. `paths[0]` mirrors `protectedPath`, `paths[1..]`
    // mirror `addedProtectedPath`. Modes are preserved by index across saves.
    paths: ProtectedPathEntry[];
    settingsVersion: typeof SETTINGS_VERSION;
}

export const DEFAULT_SETTINGS: PasswordPluginSettings = {
    protectedPath: ROOT_PATH,
    addedProtectedPath: [],
    protectEnabled: false,
    password: '',
    passwordData: null,
    lang: 'auto',
    autoLockInterval: 0,
    pwdHintQuestion: '',
    paths: [{ path: ROOT_PATH, mode: 'session' }],
    settingsVersion: SETTINGS_VERSION,
};

// Loaded `data.json` may be from any prior version. Build a v3-shaped settings
// object that is safe to assign to `plugin.settings` directly.
export function migrateSettings(raw: unknown): PasswordPluginSettings {
    const rawObj: Record<string, unknown> =
        raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {};

    // Detect the input's version *before* merging with defaults — Object.assign
    // would otherwise inherit DEFAULT_SETTINGS.settingsVersion and skip the
    // pre-v3 migration branch.
    const inputVersion =
        typeof rawObj.settingsVersion === 'number' ? rawObj.settingsVersion : 0;

    const merged: PasswordPluginSettings = Object.assign(
        {},
        DEFAULT_SETTINGS,
        rawObj
    ) as PasswordPluginSettings;

    if (inputVersion < SETTINGS_VERSION) {
        merged.paths = buildPathsFromLegacy(
            merged.protectedPath,
            merged.addedProtectedPath
        );
        merged.settingsVersion = SETTINGS_VERSION;
    } else {
        // Already v3+. Trust `paths` but normalise — drop empty entries beyond
        // the first slot, cap at ADD_PATH_MAX + 1 (one primary + N added).
        merged.paths = (merged.paths ?? []).slice(0, ADD_PATH_MAX + 1).map((entry, idx) => ({
            path: typeof entry?.path === 'string' && entry.path.trim() !== ''
                ? entry.path
                : (idx === 0 ? ROOT_PATH : ''),
            mode: entry?.mode === 'encrypted' ? 'encrypted' : 'session',
        }));
        if (merged.paths.length === 0) {
            merged.paths = [{ path: ROOT_PATH, mode: 'session' }];
        }
    }

    return merged;
}

function buildPathsFromLegacy(
    protectedPath: string,
    addedProtectedPath: string[]
): ProtectedPathEntry[] {
    const primary = (protectedPath ?? '').trim() || ROOT_PATH;
    const result: ProtectedPathEntry[] = [{ path: primary, mode: 'session' }];
    for (const p of addedProtectedPath ?? []) {
        if (typeof p !== 'string') continue;
        if (p.trim() === '') continue;
        result.push({ path: p, mode: 'session' });
        if (result.length >= ADD_PATH_MAX + 1) break;
    }
    return result;
}

// Rebuilds `paths` from the legacy fields, preserving any existing mode by
// index. Used by `saveSettings` in Phase 1 so the legacy UI's writes to
// `protectedPath` / `addedProtectedPath` propagate into `paths` without
// dropping mode information set elsewhere. Phase 3 will flip the mirror
// direction.
export function mirrorLegacyToPaths(settings: PasswordPluginSettings): void {
    const oldPaths = settings.paths ?? [];
    const next: ProtectedPathEntry[] = [
        {
            path: settings.protectedPath || ROOT_PATH,
            mode: oldPaths[0]?.mode ?? 'session',
        },
    ];
    for (let i = 0; i < settings.addedProtectedPath.length && i < ADD_PATH_MAX; i++) {
        next.push({
            path: settings.addedProtectedPath[i],
            mode: oldPaths[i + 1]?.mode ?? 'session',
        });
    }
    settings.paths = next;
}
