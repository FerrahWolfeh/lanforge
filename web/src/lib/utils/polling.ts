/**
 * Smart polling and debouncing utilities.
 * Designed to minimize CPU and network overhead on SBC router appliances.
 */

/**
 * Creates a smart polling interval that automatically pauses when the browser
 * tab is hidden or minimized, and triggers an immediate refresh when the user
 * returns to the tab.
 *
 * @param callback Function to invoke on each tick (and on visibility restore); may return a Promise
 * @param intervalMs Interval in milliseconds
 * @param immediateOnVisible Whether to immediately invoke callback when tab becomes visible (default: true)
 * @returns Cleanup function to be called in onDestroy or $effect cleanup
 */
export function createPolling(
	callback: () => void | Promise<unknown>,
	intervalMs: number,
	immediateOnVisible: boolean = true
): () => void {
	if (typeof window === "undefined") return () => {};

	// A tick is skipped while the previous callback's promise is still pending.
	let pending = false;
	const run = () => {
		if (pending) return;
		pending = true;
		Promise.resolve()
			.then(callback)
			.catch(() => {})
			.finally(() => {
				pending = false;
			});
	};

	const id = setInterval(() => {
		if (!document.hidden) run();
	}, intervalMs);

	const handleVisibilityChange = () => {
		if (immediateOnVisible && !document.hidden) run();
	};

	document.addEventListener("visibilitychange", handleVisibilityChange);

	return () => {
		clearInterval(id);
		document.removeEventListener("visibilitychange", handleVisibilityChange);
	};
}

/**
 * Creates a debounced version of a function with trailing edge execution.
 *
 * @param fn Function to debounce
 * @param delayMs Delay in milliseconds
 */
export function createDebounce<T extends (...args: any[]) => void>(
	fn: T,
	delayMs: number
): ((...args: Parameters<T>) => void) & { cancel: () => void } {
	let timer: ReturnType<typeof setTimeout> | null = null;

	const debounced = (...args: Parameters<T>) => {
		if (timer) clearTimeout(timer);
		timer = setTimeout(() => {
			timer = null;
			fn(...args);
		}, delayMs);
	};

	debounced.cancel = () => {
		if (timer) {
			clearTimeout(timer);
			timer = null;
		}
	};

	return debounced;
}

/**
 * Request-sequence guard: take an id before an `await`, and drop the response
 * if `isCurrent(id)` is false afterwards (a newer request started, or `next()`
 * was called on destroy / param change).
 */
export function createSequence() {
	let current = 0;
	return {
		next: () => ++current,
		isCurrent: (id: number) => id === current
	};
}
