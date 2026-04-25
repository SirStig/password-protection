// Minimal Obsidian runtime mock for unit tests. Only exports the surface
// that src/* code touches — anything else should surface as an error so
// non-isolated code paths do not silently slip into shared modules.

export function normalizePath(p: string): string {
    if (p === undefined || p === null) return '/';
    let s = String(p);
    s = s.replace(/\\/g, '/');
    s = s.replace(/\/+/g, '/');
    s = s.replace(/^\.\//, '');
    if (s === '' || s === '.') return '/';
    if (s.length > 1 && s.endsWith('/')) s = s.slice(0, -1);
    return s;
}
