import { App, Component, MarkdownRenderer, Modal, Setting, setIcon } from 'obsidian';

// Renders a small "?" extra-button on a Setting that, when clicked, opens
// a modal with markdown-rendered help content. Use sparingly — only on
// settings whose meaning isn't obvious from name + description.
export class HelpModal extends Modal {
    private renderComponent: Component | null = null;

    constructor(
        app: App,
        private title: string,
        private markdown: string,
        private closeLabel: string
    ) {
        super(app);
    }

    async onOpen() {
        const { contentEl } = this;
        contentEl.empty();
        contentEl.addClass('pw-help-modal');
        contentEl.createEl('h2', { text: this.title });

        const body = contentEl.createDiv({ cls: 'pw-help-body' });
        // MarkdownRenderer.renderMarkdown owns lifecycle of any interactive
        // widgets it renders via the `component` argument. We give it a
        // dedicated Component we can unload when the modal closes.
        this.renderComponent = new Component();
        this.renderComponent.load();
        try {
            await MarkdownRenderer.renderMarkdown(
                this.markdown,
                body,
                '',
                this.renderComponent
            );
        } catch {
            body.setText(this.markdown);
        }

        new Setting(contentEl).addButton((btn) =>
            btn.setButtonText(this.closeLabel).setCta().onClick(() => this.close())
        );
    }

    onClose() {
        this.renderComponent?.unload();
        this.renderComponent = null;
        this.contentEl.empty();
    }
}

// The help icon lives inside the Setting's name element, NOT controlEl, so
// it remains clickable even when the setting is disabled (e.g. while
// protection is on the auto-lock / hint rows are read-only). Reading help
// shouldn't require unlocking.
export function addHelpIcon(
    setting: Setting,
    app: App,
    title: string,
    markdown: string,
    closeLabel = 'Got it'
): Setting {
    const badge = setting.nameEl.createSpan({ cls: 'pw-help-badge' });
    badge.setAttr('role', 'button');
    badge.setAttr('tabindex', '0');
    badge.setAttr('aria-label', title);
    badge.title = title;
    setIcon(badge, 'help-circle');
    const open = (e: Event) => {
        e.stopPropagation();
        e.preventDefault();
        new HelpModal(app, title, markdown, closeLabel).open();
    };
    badge.addEventListener('click', open);
    badge.addEventListener('keydown', (e: KeyboardEvent) => {
        if (e.key === 'Enter' || e.key === ' ') open(e);
    });
    return setting;
}
