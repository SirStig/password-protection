import { describe, expect, it } from 'vitest';
import {
    DEFAULT_SETTINGS,
    migrateSettings,
    mirrorLegacyToPaths,
    mirrorPathsToLegacy,
    SETTINGS_VERSION,
    PasswordPluginSettings,
} from '../src/settings';

describe('migrateSettings', () => {
    it('returns defaults for an empty data file', () => {
        const result = migrateSettings(undefined);
        expect(result.settingsVersion).toBe(SETTINGS_VERSION);
        expect(result.paths).toEqual(DEFAULT_SETTINGS.paths);
        expect(result.protectEnabled).toBe(false);
    });

    it('migrates v2 settings (no settingsVersion) to v3 with all paths in session mode', () => {
        const v2 = {
            protectedPath: 'private',
            addedProtectedPath: ['journal', 'notes/secret'],
            protectEnabled: true,
            password: '',
            passwordData: null,
            lang: 'auto',
            autoLockInterval: 5,
            pwdHintQuestion: '',
        };
        const result = migrateSettings(v2);

        expect(result.settingsVersion).toBe(SETTINGS_VERSION);
        expect(result.paths).toEqual([
            { path: 'private', mode: 'session' },
            { path: 'journal', mode: 'session' },
            { path: 'notes/secret', mode: 'session' },
        ]);
        // Legacy fields preserved.
        expect(result.protectedPath).toBe('private');
        expect(result.addedProtectedPath).toEqual(['journal', 'notes/secret']);
    });

    it('drops empty addedProtectedPath entries during migration', () => {
        const v2 = {
            protectedPath: '/',
            addedProtectedPath: ['', 'safe', '   '],
        };
        const result = migrateSettings(v2);
        // Primary always present; only the non-empty added entry kept.
        expect(result.paths).toEqual([
            { path: '/', mode: 'session' },
            { path: 'safe', mode: 'session' },
        ]);
    });

    it('preserves explicit modes when settings are already v3', () => {
        const v3 = {
            ...DEFAULT_SETTINGS,
            protectedPath: 'private',
            addedProtectedPath: ['journal'],
            paths: [
                { path: 'private', mode: 'encrypted' },
                { path: 'journal', mode: 'session' },
            ],
            settingsVersion: 3,
        };
        const result = migrateSettings(v3);
        expect(result.paths).toEqual([
            { path: 'private', mode: 'encrypted' },
            { path: 'journal', mode: 'session' },
        ]);
    });

    it('coerces unknown mode values back to session', () => {
        const v3 = {
            ...DEFAULT_SETTINGS,
            paths: [
                { path: 'a', mode: 'session' },
                { path: 'b', mode: 'totally-bogus' as unknown as 'session' },
            ],
            settingsVersion: 3,
        };
        const result = migrateSettings(v3);
        expect(result.paths[1].mode).toBe('session');
    });
});

describe('mirrorPathsToLegacy', () => {
    it('rebuilds legacy fields from paths', () => {
        const settings: PasswordPluginSettings = {
            ...DEFAULT_SETTINGS,
            protectedPath: 'STALE',
            addedProtectedPath: ['STALE'],
            paths: [
                { path: 'private', mode: 'encrypted' },
                { path: 'journal', mode: 'session' },
                { path: 'notes/secret', mode: 'encrypted' },
            ],
        };
        mirrorPathsToLegacy(settings);
        expect(settings.protectedPath).toBe('private');
        expect(settings.addedProtectedPath).toEqual(['journal', 'notes/secret']);
    });

    it('drops empty entries when mirroring', () => {
        const settings: PasswordPluginSettings = {
            ...DEFAULT_SETTINGS,
            paths: [
                { path: 'private', mode: 'session' },
                { path: '   ', mode: 'session' },
                { path: 'journal', mode: 'session' },
            ],
        };
        mirrorPathsToLegacy(settings);
        expect(settings.protectedPath).toBe('private');
        expect(settings.addedProtectedPath).toEqual(['journal']);
    });

    it('caps the legacy added array at ADD_PATH_MAX entries even when paths has more', () => {
        const settings: PasswordPluginSettings = {
            ...DEFAULT_SETTINGS,
            paths: Array.from({ length: 12 }, (_, i) => ({
                path: `p${i}`,
                mode: 'session' as const,
            })),
        };
        mirrorPathsToLegacy(settings);
        expect(settings.protectedPath).toBe('p0');
        // ADD_PATH_MAX is 6 — so legacy holds p1..p6.
        expect(settings.addedProtectedPath).toEqual(['p1', 'p2', 'p3', 'p4', 'p5', 'p6']);
        // The remaining entries (p7..p11) live only in `paths`.
        expect(settings.paths).toHaveLength(12);
    });

    it('falls back to root when paths is empty', () => {
        const settings: PasswordPluginSettings = {
            ...DEFAULT_SETTINGS,
            paths: [],
        };
        mirrorPathsToLegacy(settings);
        expect(settings.protectedPath).toBe('/');
        expect(settings.addedProtectedPath).toEqual([]);
    });
});

describe('mirrorLegacyToPaths', () => {
    it('preserves modes by index when legacy fields change', () => {
        const settings: PasswordPluginSettings = {
            ...DEFAULT_SETTINGS,
            protectedPath: 'private',
            addedProtectedPath: ['journal', 'notes'],
            paths: [
                { path: 'private', mode: 'encrypted' },
                { path: 'journal', mode: 'session' },
                { path: 'notes', mode: 'encrypted' },
            ],
        };
        // Simulate the legacy UI editing the primary path text input.
        settings.protectedPath = 'private-renamed';
        mirrorLegacyToPaths(settings);
        expect(settings.paths).toEqual([
            { path: 'private-renamed', mode: 'encrypted' },
            { path: 'journal', mode: 'session' },
            { path: 'notes', mode: 'encrypted' },
        ]);
    });

    it('defaults newly added legacy entries to session mode', () => {
        const settings: PasswordPluginSettings = {
            ...DEFAULT_SETTINGS,
            protectedPath: '/',
            addedProtectedPath: ['extra-1', 'extra-2'],
            paths: [{ path: '/', mode: 'session' }],
        };
        mirrorLegacyToPaths(settings);
        expect(settings.paths).toEqual([
            { path: '/', mode: 'session' },
            { path: 'extra-1', mode: 'session' },
            { path: 'extra-2', mode: 'session' },
        ]);
    });
});
