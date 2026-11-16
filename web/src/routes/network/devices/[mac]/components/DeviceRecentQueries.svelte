<script lang="ts">
	import { onDestroy } from "svelte";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import { Switch } from "$lib/components/ui/switch";
	import { dnsQueryLog, dnsLogSseUrl } from "$lib/api/client";
	import type { DnsQueryLogEntry } from "$lib/api/types";

	/** The device's latest DNS queries, then live ones as they arrive. */
	let {
		mac,
		loggingOff = false,
		mutedDomains = 0,
		onToggleLogging,
	}: {
		mac: string;
		loggingOff?: boolean;
		mutedDomains?: number;
		/** Absent when the session may not change it. */
		onToggleLogging?: (off: boolean) => void;
	} = $props();

	const KEEP = 8;
	let entries = $state<DnsQueryLogEntry[]>([]);
	let live = $state(false);
	let source: EventSource | null = null;

	function stop() {
		source?.close();
		source = null;
		live = false;
	}

	async function start(target: string) {
		stop();
		entries = [];
		try {
			entries = (await dnsQueryLog({ client: target, limit: KEEP })).entries;
		} catch {
			// The live stream still fills the list.
		}
		try {
			source = new EventSource(dnsLogSseUrl({ client: target }));
			source.onopen = () => (live = true);
			source.onerror = () => (live = false);
			source.onmessage = (event) => {
				try {
					const e = JSON.parse(event.data);
					entries = [
						{
							timestamp: Number(e.timestamp),
							src_ip: String(e.src_ip),
							src_mac: e.src_mac ?? null,
							domain: String(e.domain ?? ""),
							qtype: e.qtype,
							result: String(e.result ?? "").toLowerCase(),
							upstream_us: Number(e.upstream_us ?? 0),
							cached: Boolean(e.cached),
							repeats: 1,
						},
						...entries,
					].slice(0, KEEP);
				} catch {
					// a malformed line is skipped
				}
			};
		} catch {
			// no SSE: the list stays as loaded
		}
	}

	$effect(() => {
		start(mac);
		return stop;
	});
	onDestroy(stop);

	const time = (ts: number) =>
		new Date((ts < 10_000_000_000 ? ts * 1000 : ts)).toLocaleTimeString([], {
			hour: "2-digit",
			minute: "2-digit",
			second: "2-digit",
		});

	function tone(result: string): string {
		if (result === "blocked" || result === "cachedblock") return "bg-danger/10 text-danger";
		if (result === "nxdomain" || result === "error") return "bg-warning/10 text-warning";
		return "bg-muted text-muted-foreground";
	}
	const label = (result: string) => (result === "cachedblock" ? "blocked" : result);
</script>

<section class="rounded-lg border border-border bg-card">
	<header class="flex items-center justify-between gap-2 border-b border-border px-3 py-2.5">
		<h2 class="flex items-center gap-2 text-sm font-semibold">
			<ActivityIcon class="size-4 text-muted-foreground" />Recent queries
		</h2>
		{#if live}
			<span class="flex items-center gap-1.5 text-xs text-muted-foreground">
				<span class="size-1.5 rounded-full bg-success"></span>live
			</span>
		{/if}
	</header>

	{#if loggingOff}
		<p class="p-3 text-sm text-muted-foreground">Queries from this device are not logged.</p>
	{:else if entries.length === 0}
		<p class="p-3 text-sm text-muted-foreground">No queries logged yet.</p>
	{:else}
		<ul class="divide-y divide-border">
			{#each entries as e, i (`${e.timestamp}-${e.domain}-${e.qtype}-${i}`)}
				<li class="flex items-center gap-3 px-3 py-2 text-xs">
					<span class="shrink-0 tabular-nums text-muted-foreground">{time(e.timestamp)}</span>
					<span class="min-w-0 flex-1 truncate font-mono" title={e.domain}>{e.domain}</span>
					<span class="hidden shrink-0 text-muted-foreground sm:inline">{e.qtype}</span>
					<span class="shrink-0 rounded px-1.5 py-0.5 {tone(String(e.result))}">{label(String(e.result))}</span>
				</li>
			{/each}
		</ul>
	{/if}

	<footer class="flex flex-wrap items-center justify-between gap-2 border-t border-border px-3 py-2 text-xs text-muted-foreground">
		<label class="flex items-center gap-2">
			<Switch
				checked={loggingOff}
				disabled={!onToggleLogging}
				onCheckedChange={(off) => onToggleLogging?.(off)}
			/>
			Don't log this device
		</label>
		{#if mutedDomains > 0}
			<span>{mutedDomains} {mutedDomains === 1 ? "domain" : "domains"} not logged</span>
		{/if}
	</footer>
</section>
