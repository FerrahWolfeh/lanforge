import { toast } from "svelte-sonner";

/**
 * Formats a byte size into a human-readable string (B, KB, MB, GB, TB).
 */
export function formatBytes(bytes: number | null | undefined): string {
	if (!bytes || bytes <= 0 || isNaN(bytes)) return "0 B";
	const k = 1024;
	const sizes = ["B", "KB", "MB", "GB", "TB"];
	const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1);
	return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

/**
 * Formats duration in seconds into human-readable uptime string (e.g. "3d 4h 12m", "2h 30m", "45s").
 */
export function formatUptime(secs: number | null | undefined): string {
	if (secs === null || secs === undefined || isNaN(secs) || secs < 0) return "—";
	if (secs === 0) return "0s";
	const d = Math.floor(secs / 86400);
	const h = Math.floor((secs % 86400) / 3600);
	const m = Math.floor((secs % 3600) / 60);
	const s = Math.floor(secs % 60);

	if (d > 0) return `${d}d ${h}h ${m}m`;
	if (h > 0) return m > 0 ? `${h}h ${m}m` : `${h}h`;
	if (m > 0) return s > 0 ? `${m}m ${s}s` : `${m}m`;
	return `${s}s`;
}

/**
 * Formats an epoch timestamp or ISO date string into a relative elapsed time string
 * (e.g. "Just now", "45s ago", "12m ago", "3h ago", "2d ago").
 */
export function formatTimeAgo(ts: number | string | Date | null | undefined): string {
	if (!ts) return "—";
	let ms: number;
	if (typeof ts === "number") {
		// Detect seconds vs milliseconds
		ms = ts < 10_000_000_000 ? ts * 1000 : ts;
	} else if (typeof ts === "string") {
		ms = Date.parse(ts);
	} else if (ts instanceof Date) {
		ms = ts.getTime();
	} else {
		return "—";
	}

	if (isNaN(ms) || ms === 0) return "Never";

	const secsAgo = Math.floor((Date.now() - ms) / 1000);
	if (secsAgo < 0 || secsAgo < 10) return "Just now";
	if (secsAgo < 60) return `${secsAgo}s ago`;
	const minsAgo = Math.floor(secsAgo / 60);
	if (minsAgo < 60) return `${minsAgo}m ago`;
	const hoursAgo = Math.floor(minsAgo / 60);
	if (hoursAgo < 24) return `${hoursAgo}h ago`;
	const daysAgo = Math.floor(hoursAgo / 24);
	if (daysAgo < 30) return `${daysAgo}d ago`;
	return `${Math.floor(daysAgo / 30)}mo ago`;
}

/**
 * Copies a string to the clipboard and shows an optional toast notification.
 */
export async function copyToClipboard(text: string, label?: string): Promise<boolean> {
	if (!navigator?.clipboard) {
		toast.error("Clipboard API is not supported in this browser");
		return false;
	}
	try {
		await navigator.clipboard.writeText(text);
		toast.success(label ? `Copied ${label}` : "Copied to clipboard");
		return true;
	} catch (err: any) {
		toast.error(err?.message || "Failed to copy to clipboard");
		return false;
	}
}

/**
 * Splits a comma-separated string into a trimmed, non-empty list of items.
 */
export function parseCsvList(str: string | null | undefined): string[] {
	if (!str) return [];
	return str
		.split(",")
		.map((s) => s.trim())
		.filter(Boolean);
}
