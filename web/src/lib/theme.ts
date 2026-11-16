import { toggleMode } from 'mode-watcher';

/**
 * Switch between dark and light with a short crossfade. The page area has its own
 * route-change animation (slide + fade); `data-vt="theme"` tells the stylesheet to use a
 * plain crossfade for every part of the page instead.
 */
export function switchMode(): void {
	const root = document.documentElement;
	const doc = document as Document & {
		startViewTransition?: (cb: () => void) => { finished: Promise<void> };
	};
	if (!doc.startViewTransition || matchMedia('(prefers-reduced-motion: reduce)').matches) {
		toggleMode();
		return;
	}
	root.dataset.vt = 'theme';
	doc
		.startViewTransition(() => toggleMode())
		.finished.finally(() => delete root.dataset.vt);
}
