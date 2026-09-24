/**
 * Smart polling and debouncing utilities.
 * Designed to minimize CPU and network overhead on SBC router appliances.
 */

/**
 * Creates a smart polling interval that automatically pauses when the browser
 * tab is hidden or minimized, and triggers an immediate refresh when the user
 * returns to the tab.
 *
 * @param callback Function to invoke on each tick (and on visibility restore)
 * @param intervalMs Interval in milliseconds
 * @param immediateOnVisible Whether to immediately invoke callback when tab becomes visible (default: true)
 * @returns Cleanup function to be called in onDestroy or $effect cleanup
 */
export function createPolling(
	callback: () => void,
	intervalMs: number,
	immediateOnVisible: boolean = true
): () => void {
	if (typeof window === "undefined") return () => {};

	const id = setInterval(() => {
		if (!document.hidden) {
			callback();
		}
	}, intervalMs);

	const handleVisibilityChange = () => {
		if (immediateOnVisible && !document.hidden) {
			callback();
		}
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
