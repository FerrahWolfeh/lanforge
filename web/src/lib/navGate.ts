import type { Permission } from "$lib/api/types";
import { auth } from "$lib/stores/auth.svelte";
import { capabilitiesState } from "$lib/stores/capabilities.svelte";

/** What a sidebar entry or command-palette item needs before it is offered. */
export interface NavGate {
	cap?: string | string[];
	/** Hidden from sessions the server would refuse the page's reads to. */
	perm?: Permission;
}

/** Whether the session may use the entry and the daemon has the capability behind it. */
export function isNavVisible(item: NavGate): boolean {
	if (item.perm && !auth.can(item.perm)) return false;
	if (!item.cap) return true;
	if (Array.isArray(item.cap)) {
		return item.cap.some((c) => capabilitiesState.isEnabled(c));
	}
	return capabilitiesState.isEnabled(item.cap);
}

/** Shown only because the dev capabilities override is on: the daemon does not have the capability. */
export function isNavDebugOnly(item: NavGate): boolean {
	return !!(
		capabilitiesState.debugMode &&
		item.cap &&
		(Array.isArray(item.cap)
			? !capabilitiesState.isAnyActualEnabled(item.cap)
			: !capabilitiesState.isActualEnabled(item.cap))
	);
}
