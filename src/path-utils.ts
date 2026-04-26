import { normalizePath } from 'obsidian';

export const ROOT_PATH = normalizePath('/');
// Cap on the legacy `addedProtectedPath: string[]` field (preserved for v2
// downgrade safety). The v3 `paths` array can hold up to MAX_PATHS entries.
export const ADD_PATH_MAX = 6;
export const MAX_PATHS = 30;

export type ProtectionMode = 'session' | 'encrypted';

export interface ProtectedPathEntry {
    path: string;
    mode: ProtectionMode;
}

export function isChildPath(path: string, protectedPath: string): boolean {
    if (protectedPath.length > 0 && path.length >= protectedPath.length) {
        if (path.toLowerCase().startsWith(protectedPath.toLowerCase())) {
            if (path.length === protectedPath.length) return true;
            const sep = path[protectedPath.length];
            if (sep === '/' || sep === '\\' || sep === '.') return true;
        }
    }
    return false;
}

export function isProtectedPath(
    filePath: string,
    primaryPath: string,
    addedPaths: string[]
): boolean {
    if (!filePath) return false;

    if (normalizePath(primaryPath) === ROOT_PATH) return true;
    for (const p of addedPaths) {
        if (normalizePath(p) === ROOT_PATH) return true;
    }

    const path = normalizePath(filePath);
    if (isChildPath(path, normalizePath(primaryPath))) return true;

    for (const rawPath of addedPaths) {
        const pp = normalizePath(rawPath.trim());
        if (!pp) continue;
        if (path.length < pp.length) continue;
        if (isChildPath(path, pp)) return true;
    }

    return false;
}

export function removeFileExtension(fullPath: string): string {
    const lastDot = fullPath.lastIndexOf('.');
    const lastSep = Math.max(fullPath.lastIndexOf('/'), fullPath.lastIndexOf('\\'));
    if (lastDot === -1 || lastDot <= lastSep) return fullPath;
    return fullPath.substring(0, lastDot);
}

export function replaceProtectedPath(
    oldPath: string,
    newPath: string,
    primaryPath: string,
    addedPaths: string[]
): { primaryPath: string; addedPaths: string[] } | null {
    if (!oldPath || !newPath) return null;

    const oldNorm = normalizePath(removeFileExtension(oldPath));
    const newNorm = normalizePath(removeFileExtension(newPath));

    if (
        normalizePath(primaryPath) !== ROOT_PATH &&
        oldNorm.toLowerCase() === normalizePath(primaryPath).toLowerCase()
    ) {
        return { primaryPath: newNorm, addedPaths };
    }

    for (let i = 0; i < addedPaths.length; i++) {
        if (
            normalizePath(addedPaths[i]) !== ROOT_PATH &&
            oldNorm.toLowerCase() === normalizePath(addedPaths[i]).toLowerCase()
        ) {
            const updated = [...addedPaths];
            updated[i] = newNorm;
            return { primaryPath, addedPaths: updated };
        }
    }

    return null;
}

// True if `filePath` is covered by any entry in the `paths` list. Mirrors
// the semantics of `isProtectedPath` but reads from the v3 entries array.
export function isProtectedByEntries(
    filePath: string,
    paths: ProtectedPathEntry[]
): boolean {
    if (!filePath) return false;
    if (anyEntryIsRoot(paths)) return true;

    const target = normalizePath(filePath);
    for (const entry of paths) {
        const raw = (entry.path ?? '').trim();
        if (raw === '') continue;
        const norm = normalizePath(raw);
        if (norm === ROOT_PATH) return true;
        if (target.length < norm.length) continue;
        if (isChildPath(target, norm)) return true;
    }
    return false;
}

// True if any entry's path normalises to vault root ('/').
export function anyEntryIsRoot(paths: ProtectedPathEntry[]): boolean {
    for (const entry of paths) {
        const raw = (entry.path ?? '').trim();
        if (raw === '') continue;
        if (normalizePath(raw) === ROOT_PATH) return true;
    }
    return false;
}

// Updates entries whose path matches a renamed folder. Returns a new array
// or null if nothing changed. Mode is preserved per entry.
export function replaceProtectedPathInEntries(
    oldPath: string,
    newPath: string,
    paths: ProtectedPathEntry[]
): ProtectedPathEntry[] | null {
    if (!oldPath || !newPath) return null;

    const oldNorm = normalizePath(removeFileExtension(oldPath));
    const newNorm = normalizePath(removeFileExtension(newPath));

    let changed = false;
    const result = paths.map((entry) => {
        const norm = normalizePath((entry.path ?? '').trim());
        if (norm !== ROOT_PATH && norm.toLowerCase() === oldNorm.toLowerCase()) {
            changed = true;
            return { path: newNorm, mode: entry.mode };
        }
        return entry;
    });
    return changed ? result : null;
}

// Returns the mode of the longest matching protected path, or null if the
// file is not under any protected path. Used only to decide the *folder
// default* for new files. Whether an existing file is currently encrypted
// is determined from the file's on-disk sentinel header, not from this.
export function modeForFile(
    filePath: string,
    paths: ProtectedPathEntry[]
): ProtectionMode | null {
    if (!filePath || paths.length === 0) return null;

    const target = normalizePath(filePath);

    let bestMatch: ProtectedPathEntry | null = null;
    let bestLen = -1;

    for (const entry of paths) {
        const raw = (entry.path ?? '').trim();
        // Empty path entries are treated as "no rule" — distinct from vault
        // root, which the user must spell as '/'. Otherwise normalizePath('')
        // would yield '/' and silently catch everything.
        if (raw === '') continue;

        const norm = normalizePath(raw);

        // Vault root matches every file. Length 1 ('/') so any deeper match wins.
        if (norm === ROOT_PATH) {
            if (bestLen < 1) {
                bestMatch = entry;
                bestLen = 1;
            }
            continue;
        }

        if (isChildPath(target, norm) && norm.length > bestLen) {
            bestMatch = entry;
            bestLen = norm.length;
        }
    }

    return bestMatch ? bestMatch.mode : null;
}
