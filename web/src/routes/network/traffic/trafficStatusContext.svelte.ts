import { getContext, setContext } from "svelte";
import type { TrafficStatusResponse } from "$lib/api/types";

/** Traffic status owned by the traffic layout (single poll) and read by its pages. */
export interface TrafficStatusShare {
	value: TrafficStatusResponse | null;
	refresh: () => Promise<void>;
}

const KEY = Symbol("traffic-status");

export function provideTrafficStatus(share: TrafficStatusShare) {
	setContext(KEY, share);
}

export function useTrafficStatus(): TrafficStatusShare {
	return getContext<TrafficStatusShare>(KEY);
}
