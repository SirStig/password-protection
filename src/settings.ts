import type { LangTypeAndAuto } from '../i18n';
import type { PasswordData } from './crypto';
import { ROOT_PATH, ADD_PATH_MAX, MAX_PATHS, ProtectedPathEntry } from './path-utils';

export const SETTINGS_VERSION = 3 as const;

export interface PasswordPluginSettings {
    // Legacy fields (v2). After v3 they are derived mirrors of `paths` —
    // kept in `data.json` so a downgrade to the v2 plugin still finds the
    // primary path and the first ADD_PATH_MAX added paths.
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

    // v3: per-path mode. Source of truth; the legacy fields above are
    // recomputed from this array on every save.
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
        // Already v3+. Trust `paths` but normalise — drop empties, coerce
        // bad mode values, cap at MAX_PATHS.
        merged.paths = (merged.paths ?? [])
            .slice(0, MAX_PATHS)
            .map((entry): ProtectedPathEntry => ({
                path: typeof entry?.path === 'string' ? entry.path : '',
                mode: entry?.mode === 'encrypted' ? 'encrypted' : 'session',
            }))
            .filter((e) => e.path.trim() !== '');
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
        if (result.length >= MAX_PATHS) break;
    }
    return result;
}

// Rebuilds the legacy fields from `paths` — `paths` is the v3 source of
// truth. Legacy fields stay in `data.json` so a downgrade to the v2 plugin
// still finds the primary path and the first ADD_PATH_MAX added paths;
// entries beyond that are visible only to v3+. Empty/whitespace entries
// are filtered out.
export function mirrorPathsToLegacy(settings: PasswordPluginSettings): void {
    const live = (settings.paths ?? []).filter(
        (e) => typeof e?.path === 'string' && e.path.trim() !== ''
    );
    settings.protectedPath = live[0]?.path ?? ROOT_PATH;
    settings.addedProtectedPath = live.slice(1, 1 + ADD_PATH_MAX).map((e) => e.path);
}

// Kept for backwards-compat with any external callers that may have
// imported it. Internal code uses `mirrorPathsToLegacy` now.
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
