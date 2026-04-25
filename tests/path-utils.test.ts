import { describe, expect, it } from 'vitest';
import {
    isChildPath,
    isProtectedPath,
    modeForFile,
    removeFileExtension,
    replaceProtectedPath,
    ProtectedPathEntry,
} from '../src/path-utils';

describe('isChildPath', () => {
    it('matches identical paths', () => {
        expect(isChildPath('foo/bar', 'foo/bar')).toBe(true);
    });

    it('matches a child file with .md extension via the dot separator rule', () => {
        expect(isChildPath('foo/bar.md', 'foo/bar')).toBe(true);
    });

    it('matches a deeper file', () => {
        expect(isChildPath('foo/bar/baz.md', 'foo/bar')).toBe(true);
    });

    it('rejects a sibling whose prefix happens to match', () => {
        expect(isChildPath('foobar', 'foo')).toBe(false);
    });

    it('is case-insensitive', () => {
        expect(isChildPath('Foo/Bar.md', 'foo/bar')).toBe(true);
    });
});

describe('isProtectedPath', () => {
    it('treats the vault root as protecting everything', () => {
        expect(isProtectedPath('any/file.md', '/', [])).toBe(true);
    });

    it('respects an added root path', () => {
        expect(isProtectedPath('any/file.md', 'safe', ['/'])).toBe(true);
    });

    it('matches against the primary path', () => {
        expect(isProtectedPath('safe/note.md', 'safe', [])).toBe(true);
    });

    it('matches against an added path', () => {
        expect(isProtectedPath('extra/note.md', 'safe', ['extra'])).toBe(true);
    });

    it('returns false for paths outside any rule', () => {
        expect(isProtectedPath('public/note.md', 'safe', ['extra'])).toBe(false);
    });
});

describe('modeForFile', () => {
    const paths: ProtectedPathEntry[] = [
        { path: '/', mode: 'session' },
        { path: 'secrets', mode: 'encrypted' },
        { path: 'secrets/casual', mode: 'session' },
    ];

    it('returns the most specific (longest) match', () => {
        expect(modeForFile('secrets/casual/foo.md', paths)).toBe('session');
    });

    it('returns the encrypted mode for a deeper file under secrets', () => {
        expect(modeForFile('secrets/private.md', paths)).toBe('encrypted');
    });

    it('returns the root mode for files outside any specific rule', () => {
        expect(modeForFile('elsewhere/note.md', paths)).toBe('session');
    });

    it('returns null when no path is configured', () => {
        expect(modeForFile('any.md', [])).toBeNull();
    });

    it('returns null when configured paths do not match and no root rule', () => {
        const pathsNoRoot: ProtectedPathEntry[] = [
            { path: 'secrets', mode: 'encrypted' },
        ];
        expect(modeForFile('elsewhere.md', pathsNoRoot)).toBeNull();
    });

    it('ignores empty path entries', () => {
        const pathsWithEmpty: ProtectedPathEntry[] = [
            { path: '', mode: 'encrypted' },
            { path: 'secrets', mode: 'encrypted' },
        ];
        expect(modeForFile('elsewhere.md', pathsWithEmpty)).toBeNull();
        expect(modeForFile('secrets/x.md', pathsWithEmpty)).toBe('encrypted');
    });
});

describe('removeFileExtension', () => {
    it('strips a trailing extension', () => {
        expect(removeFileExtension('foo/bar.md')).toBe('foo/bar');
    });

    it('leaves a folder path unchanged', () => {
        expect(removeFileExtension('foo/bar')).toBe('foo/bar');
    });

    it('does not strip a dot in a folder name', () => {
        expect(removeFileExtension('foo.bar/baz')).toBe('foo.bar/baz');
    });
});

describe('replaceProtectedPath', () => {
    it('updates the primary path on rename', () => {
        const result = replaceProtectedPath('old', 'new', 'old', []);
        expect(result).toEqual({ primaryPath: 'new', addedPaths: [] });
    });

    it('updates an added path on rename', () => {
        const result = replaceProtectedPath('old', 'new', '/', ['old', 'other']);
        expect(result).toEqual({ primaryPath: '/', addedPaths: ['new', 'other'] });
    });

    it('returns null when no protected path matches', () => {
        expect(replaceProtectedPath('other', 'new', '/', ['safe'])).toBeNull();
    });
});
