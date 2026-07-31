/**
 * Global SSE event feed store.
 * Manages a single long-lived connection to GET /api/v1/events.
 * Re-connects automatically with Last-Event-ID on drop.
 */

import { eventsUrl } from '$lib/api/client';
import { parseTimedEvent, type EventKind, type SseEvent } from '$lib/api/types';

const MAX_EVENTS = 200;

function createEventsStore() {
	let events = $state<SseEvent[]>([]);
	let connected = $state(false);
	let lastEventId = $state<string | null>(null);

	let es: EventSource | null = null;
	let retryTimeout: ReturnType<typeof setTimeout> | null = null;
	let retryDelay = 2000;

	function connect() {
		if (typeof EventSource === 'undefined') return;

		const params: { initial?: number; filter?: string } = { initial: 50 };
		const url = eventsUrl(params);

		es = new EventSource(url, { withCredentials: true });

		es.onopen = () => {
			connected = true;
			retryDelay = 2000;
		};

		es.onerror = () => {
			connected = false;
			es?.close();
			es = null;
			retryTimeout = setTimeout(() => connect(), retryDelay);
			retryDelay = Math.min(retryDelay * 2, 30_000);
		};

		es.onmessage = (e) => handleEvent('message', e);

		const knownKinds: EventKind[] = [
			'DeviceOnline',
			'DeviceOffline',
			'DeviceUpdated',
			'DevicePurged',
			'DhcpLeaseGranted',
			'DhcpLeaseReleased',
			'DnsQuery',
			'DnsBlocked',
			'DnsRewriteUpdated',
			'AdblockToggled',
			'ScanCompleted',
			'ConfigReloaded'
		];
		for (const kind of knownKinds) {
			es.addEventListener(kind, (e) => handleEvent(kind, e as MessageEvent));
		}
	}

	function handleEvent(kind: string, e: MessageEvent) {
		const id = e.lastEventId || String(Date.now());
		lastEventId = id;
		let raw: unknown = null;
		try {
			raw = JSON.parse(e.data);
		} catch {
			raw = { raw: e.data };
		}
		const event = parseTimedEvent(raw, id);
		// If kind from SSE header was explicitly provided and not default 'message', prefer it if parseTimedEvent couldn't extract specific kind
		if (kind !== 'message' && event.kind === 'Event') {
			event.kind = kind as EventKind;
		}
		events = [event, ...events].slice(0, MAX_EVENTS);
	}

	function disconnect() {
		if (retryTimeout) clearTimeout(retryTimeout);
		es?.close();
		es = null;
		connected = false;
	}

	return {
		get events() {
			return events;
		},
		get connected() {
			return connected;
		},
		get lastEventId() {
			return lastEventId;
		},
		connect,
		disconnect
	};
}

export const eventFeed = createEventsStore();
