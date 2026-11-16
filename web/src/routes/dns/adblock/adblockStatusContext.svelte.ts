import { getContext, setContext } from "svelte";
import type { DnsAdblockStatusResponse } from "$lib/api/types";

/** Adblock status owned by the adblock layout (single poll) and read by its pages. */
export interface AdblockStatusShare {
	value: DnsAdblockStatusResponse | null;
	refresh: () => Promise<void>;
}

const KEY = Symbol("adblock-status");

export function provideAdblockStatus(share: AdblockStatusShare) {
	setContext(KEY, share);
}

export function useAdblockStatus(): AdblockStatusShare {
	return getContext<AdblockStatusShare>(KEY);
}
