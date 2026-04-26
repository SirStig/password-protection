import { App, Modal, Setting, TAbstractFile, TFile, TFolder } from 'obsidian';
import type { TransItemType } from '../i18n';
import { ROOT_PATH } from './path-utils';

// Lazy-render threshold: if the vault has more than this many indexable
// items (folders + .md files), render folders collapsed and only walk a
// folder's children when it is expanded. Eager-render-with-CSS-collapse is
// fine below this; above, the up-front DOM cost gets noticeable.
const LAZY_THRESHOLD = 1500;

// Maximum results returned in search mode — flat list, no tree.
const SEARCH_RESULT_CAP = 200;

interface PathPickerOptions {
    initialSelected: Set<string>;
    onConfirm: (selected: Set<string>) => void;
    title?: string;
    confirmLabel?: string;
    t: (key: TransItemType, vars?: Record<string, string>) => string;
}

export class PathPickerModal extends Modal {
    private selected: Set<string>;
    private opts: PathPickerOptions;
    private treeContainer!: HTMLElement;
    private resultsContainer!: HTMLElement;
    private summaryEl!: HTMLElement;
    private indexed: { folders: TFolder[]; files: TFile[] };
    private lazy: boolean;
    // Persistent expand state across re-renders.
    private expandedFolders: Set<string> = new Set();

    constructor(app: App, opts: PathPickerOptions) {
        super(app);
        this.opts = opts;
        this.selected = new Set(opts.initialSelected);
        this.indexed = this.indexVault();
        this.lazy = this.indexed.folders.length + this.indexed.files.length > LAZY_THRESHOLD;
        // Auto-expand any folder that contains a pre-selected entry, so the
        // user immediately sees their existing selections.
        this.expandedFolders.add(ROOT_PATH);
        for (const path of this.selected) {
            this.expandAncestorsOf(path);
        }
    }

    private indexVault(): { folders: TFolder[]; files: TFile[] } {
        const folders: TFolder[] = [];
        const files: TFile[] = [];
        const walk = (node: TAbstractFile) => {
            if (node instanceof TFolder) {
                folders.push(node);
                for (const child of node.children) walk(child);
            } else if (node instanceof TFile && node.extension === 'md') {
                files.push(node);
            }
        };
        walk(this.app.vault.getRoot());
        return { folders, files };
    }

    private expandAncestorsOf(path: string) {
        // Walk parent folders by string prefix. e.g. 'Secrets/personal/diary.md'
        // → expand 'Secrets', 'Secrets/personal'.
        const parts = path.split('/').filter(Boolean);
        let acc = '';
        for (let i = 0; i < parts.length - 1; i++) {
            acc = acc ? `${acc}/${parts[i]}` : parts[i];
            this.expandedFolders.add(acc);
        }
    }

    onOpen() {
        const { contentEl } = this;
        contentEl.empty();
        contentEl.addClass('pw-picker-modal');

        contentEl.createEl('h2', {
            text: this.opts.title ?? this.opts.t('picker_modal_title'),
        });

        // Search input
        const searchWrap = contentEl.createDiv({ cls: 'pw-picker-search-wrap' });
        const searchEl = searchWrap.createEl('input', { type: 'text', cls: 'pw-picker-search' });
        searchEl.placeholder = this.opts.t('picker_search_placeholder');
        searchEl.addEventListener('input', () => this.handleSearch(searchEl.value));

        // Tree / results containers (mutually exclusive)
        this.treeContainer = contentEl.createDiv({ cls: 'pw-picker-tree' });
        this.resultsContainer = contentEl.createDiv({ cls: 'pw-picker-results' });
        this.resultsContainer.style.display = 'none';

        this.renderTree();

        // Footer
        const footer = contentEl.createDiv({ cls: 'pw-picker-footer' });
        this.summaryEl = footer.createDiv({ cls: 'pw-picker-summary' });
        this.refreshSummary();

        new Setting(footer)
            .addButton((btn) =>
                btn
                    .setButtonText(this.opts.confirmLabel ?? this.opts.t('ok'))
                    .setCta()
                    .onClick(() => {
                        this.opts.onConfirm(this.selected);
                        this.close();
                    })
            )
            .addButton((btn) =>
                btn.setButtonText(this.opts.t('cancel')).onClick(() => this.close())
            );
    }

    onClose() {
        this.contentEl.empty();
    }

    // ── Tree mode ──────────────────────────────────────────────────────────

    private renderTree() {
        this.treeContainer.empty();

        // Vault root is offered as a single "Protect entire vault" checkbox
        // at the top so the user has an easy way to toggle root coverage.
        const rootRow = this.makeRowEl(this.treeContainer, 0, 'folder');
        rootRow.addClass('pw-picker-root');
        const rootSpacer = rootRow.createSpan({ cls: 'pw-picker-toggle-spacer' });
        rootSpacer.setText(' ');
        const rootCb = rootRow.createEl('input', { type: 'checkbox' });
        rootCb.checked = this.selected.has(ROOT_PATH);
        rootCb.addEventListener('change', () => {
            if (rootCb.checked) this.selected.add(ROOT_PATH);
            else this.selected.delete(ROOT_PATH);
            this.refreshSummary();
        });
        const rootLabel = rootRow.createSpan({ cls: 'pw-picker-label' });
        rootLabel.setText(this.opts.t('picker_root_label'));

        const root = this.app.vault.getRoot();
        this.renderFolderChildren(root, this.treeContainer, 0);
    }

    private renderFolderChildren(folder: TFolder, parent: HTMLElement, depth: number) {
        const sorted = [...folder.children].sort((a, b) => {
            const aIsFolder = a instanceof TFolder;
            const bIsFolder = b instanceof TFolder;
            if (aIsFolder && !bIsFolder) return -1;
            if (!aIsFolder && bIsFolder) return 1;
            return a.name.localeCompare(b.name);
        });

        for (const child of sorted) {
            if (child instanceof TFolder) {
                this.renderFolderRow(child, parent, depth);
            } else if (child instanceof TFile && child.extension === 'md') {
                this.renderFileRow(child, parent, depth);
            }
        }
    }

    private renderFolderRow(folder: TFolder, parent: HTMLElement, depth: number) {
        const row = this.makeRowEl(parent, depth, 'folder');
        const expanded = this.expandedFolders.has(folder.path);

        const toggle = row.createSpan({
            cls: 'pw-picker-toggle ' + (expanded ? 'is-expanded' : ''),
        });
        toggle.setText(expanded ? '▼' : '▶');

        const cb = row.createEl('input', { type: 'checkbox' });
        cb.checked = this.selected.has(folder.path);
        cb.addEventListener('click', (e) => e.stopPropagation());
        cb.addEventListener('change', () => {
            if (cb.checked) this.selected.add(folder.path);
            else this.selected.delete(folder.path);
            this.refreshSummary();
        });

        const label = row.createSpan({ cls: 'pw-picker-label pw-picker-folder-label' });
        label.setText('📁 ' + folder.name);

        // Children container (always present; toggled via display)
        const childrenEl = parent.createDiv({ cls: 'pw-picker-children' });
        childrenEl.style.display = expanded ? '' : 'none';

        const fillChildren = () => {
            if (childrenEl.dataset.populated === '1') return;
            childrenEl.dataset.populated = '1';
            this.renderFolderChildren(folder, childrenEl, depth + 1);
        };

        // Eager-fill mode: populate immediately, just hide via CSS.
        // Lazy-fill mode: populate on first expand to avoid up-front cost.
        if (!this.lazy || expanded) fillChildren();

        const handleToggle = () => {
            const isOpen = childrenEl.style.display !== 'none';
            if (isOpen) {
                childrenEl.style.display = 'none';
                this.expandedFolders.delete(folder.path);
                toggle.setText('▶');
                toggle.removeClass('is-expanded');
            } else {
                fillChildren();
                childrenEl.style.display = '';
                this.expandedFolders.add(folder.path);
                toggle.setText('▼');
                toggle.addClass('is-expanded');
            }
        };
        toggle.addEventListener('click', (e) => {
            e.stopPropagation();
            handleToggle();
        });
        // Make folder name clickable too (but not the checkbox).
        label.addEventListener('click', (e) => {
            e.stopPropagation();
            handleToggle();
        });
    }

    private renderFileRow(file: TFile, parent: HTMLElement, depth: number) {
        const row = this.makeRowEl(parent, depth, 'file');
        // Spacer where the toggle would be, so file rows align with folder rows.
        row.createSpan({ cls: 'pw-picker-toggle-spacer' });

        const cb = row.createEl('input', { type: 'checkbox' });
        cb.checked = this.selected.has(file.path);
        cb.addEventListener('change', () => {
            if (cb.checked) this.selected.add(file.path);
            else this.selected.delete(file.path);
            this.refreshSummary();
        });

        const label = row.createSpan({ cls: 'pw-picker-label pw-picker-file-label' });
        label.setText('📄 ' + file.name);
    }

    private makeRowEl(parent: HTMLElement, depth: number, kind: 'folder' | 'file'): HTMLElement {
        const row = parent.createDiv({ cls: `pw-picker-row pw-picker-${kind}` });
        row.style.paddingLeft = `${depth * 18 + 6}px`;
        return row;
    }

    // ── Search mode ────────────────────────────────────────────────────────

    private handleSearch(query: string) {
        const trimmed = query.trim().toLowerCase();
        if (trimmed === '') {
            this.resultsContainer.style.display = 'none';
            this.treeContainer.style.display = '';
            return;
        }
        this.treeContainer.style.display = 'none';
        this.resultsContainer.style.display = '';
        this.resultsContainer.empty();

        const candidates: { path: string; isFolder: boolean }[] = [];
        for (const folder of this.indexed.folders) {
            if (folder.path === ROOT_PATH || folder.path === '/' || folder.parent === null) continue;
            if (folder.path.toLowerCase().includes(trimmed)) {
                candidates.push({ path: folder.path, isFolder: true });
            }
        }
        for (const file of this.indexed.files) {
            if (file.path.toLowerCase().includes(trimmed)) {
                candidates.push({ path: file.path, isFolder: false });
            }
        }
        candidates.sort((a, b) => a.path.localeCompare(b.path));

        if (candidates.length === 0) {
            this.resultsContainer.createDiv({
                cls: 'pw-picker-empty',
                text: this.opts.t('picker_no_results'),
            });
            return;
        }

        const truncated = candidates.length > SEARCH_RESULT_CAP;
        const visible = truncated ? candidates.slice(0, SEARCH_RESULT_CAP) : candidates;

        for (const item of visible) {
            const row = this.resultsContainer.createDiv({
                cls: `pw-picker-row pw-picker-${item.isFolder ? 'folder' : 'file'}`,
            });
            const cb = row.createEl('input', { type: 'checkbox' });
            cb.checked = this.selected.has(item.path);
            cb.addEventListener('change', () => {
                if (cb.checked) this.selected.add(item.path);
                else this.selected.delete(item.path);
                this.refreshSummary();
            });
            const label = row.createSpan({ cls: 'pw-picker-label' });
            label.setText((item.isFolder ? '📁 ' : '📄 ') + item.path);
        }

        if (truncated) {
            this.resultsContainer.createDiv({
                cls: 'pw-picker-truncated',
                text: this.opts.t('picker_truncated', {
                    shown: String(SEARCH_RESULT_CAP),
                    total: String(candidates.length),
                }),
            });
        }
    }

    private refreshSummary() {
        const n = this.selected.size;
        this.summaryEl.setText(this.opts.t('picker_selected', { count: String(n) }));
    }
}
