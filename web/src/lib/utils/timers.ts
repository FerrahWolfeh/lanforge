/**
 * A set of pending timeouts that can be cancelled together, for follow-up refreshes that must
 * not fire after the page is gone. Call `clear` on destroy.
 */
export function createTimers() {
	const pending = new Set<ReturnType<typeof setTimeout>>();
	return {
		later(fn: () => void, ms: number) {
			const t = setTimeout(() => {
				pending.delete(t);
				fn();
			}, ms);
			pending.add(t);
		},
		clear() {
			pending.forEach(clearTimeout);
			pending.clear();
		}
	};
}
