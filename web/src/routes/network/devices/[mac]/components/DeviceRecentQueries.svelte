<script lang="ts">
	import { onDestroy } from "svelte";
	import { toast } from "svelte-sonner";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import XIcon from "@lucide/svelte/icons/x";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import * as Popover from "$lib/components/ui/popover";
	import { Switch } from "$lib/components/ui/switch";
	import { dnsQueryLog, dnsLogSseUrl, hostSet } from "$lib/api/client";
	import type { DnsQueryLogEntry } from "$lib/api/types";
	import { createSequence } from "$lib/utils";

	/** The device's latest DNS queries, then live ones as they arrive. */
	let {
		mac,
		loggingOff = false,
		ignoredDomains = [],
		canEdit = false,
		onChanged,
		onToggleLogging,
	}: {
		mac: string;
		loggingOff?: boolean;
		/** Domains whose queries are not logged for this device. */
		ignoredDomains?: string[];
		/** Absent or false when the session may not change them: the list is read-only. */
		canEdit?: boolean;
		/** Called after a muted domain was added or removed. */
		onChanged?: () => void;
		/** Absent when the session may not change it. */
		onToggleLogging?: (off: boolean) => void;
	} = $props();

	const KEEP = 8;
	let entries = $state<DnsQueryLogEntry[]>([]);
	let live = $state(false);
	let seq = 0;
	let source: EventSource | null = null;
	/** Bumped by every stop(), so a start() that was awaiting a fetch knows it is no longer wanted. */
	const generation = createSequence();
	let newDomain = $state("");

	async function changeIgnored(field: "add_ignored_log_domain" | "remove_ignored_log_domain", domain: string) {
		try {
			await hostSet(mac, field, domain);
			onChanged?.();
			return true;
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to change the muted domains");
			return false;
		}
	}

	async function addDomain(e: SubmitEvent) {
		e.preventDefault();
		const domain = newDomain.trim().toLowerCase();
		if (!domain) return;
		if (await changeIgnored("add_ignored_log_domain", domain)) newDomain = "";
	}

	function stop() {
		generation.next();
		source?.close();
		source = null;
		live = false;
	}

	async function start(target: string) {
		stop();
		const gen = generation.next();
		entries = [];
		try {
			const res = await dnsQueryLog({ client: target, limit: KEEP });
			if (!generation.isCurrent(gen)) return;
			entries = res.entries.map((e) => ({ ...e, _seq: ++seq }));
		} catch {
			// The live stream still fills the list.
		}
		if (!generation.isCurrent(gen)) return;
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
							repeats: Number(e.repeats ?? 1),
							_seq: ++seq,
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
			{#each entries as e (e._seq)}
				<li class="flex items-center gap-3 px-3 py-2 text-xs">
					<span class="shrink-0 tabular-nums text-muted-foreground">{time(e.timestamp)}</span>
					<a href={`/dns/domains/${encodeURIComponent(e.domain.replace(/\.$/, ""))}`} class="min-w-0 flex-1 truncate font-mono hover:underline" title={e.domain}>{e.domain}</a>
					{#if e.repeats > 1}
						<span class="shrink-0 tabular-nums text-muted-foreground" title="{e.repeats} identical queries, folded into one line">×{e.repeats}</span>
					{/if}
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
		<div class="flex items-center gap-3">
			{#if canEdit || ignoredDomains.length > 0}
				<Popover.Root>
					<Popover.Trigger>
						{#snippet child({ props })}
							<Button variant="ghost" size="xs" {...props}>Muted domains ({ignoredDomains.length})</Button>
						{/snippet}
					</Popover.Trigger>
					<Popover.Content align="end" class="flex w-64 flex-col gap-2 p-3 text-xs">
						<p class="font-semibold text-foreground">Queries to these domains are not logged</p>
						{#if ignoredDomains.length === 0}
							<p class="text-muted-foreground">No muted domains.</p>
						{:else}
							<ul class="flex max-h-48 flex-col gap-1 overflow-y-auto">
								{#each ignoredDomains as d (d)}
									<li class="flex items-center justify-between gap-2">
										<span class="truncate font-mono" title={d}>{d}</span>
										{#if canEdit}
											<Button
												variant="ghost"
												size="icon-xs"
												aria-label="Stop muting {d}"
												onclick={() => changeIgnored("remove_ignored_log_domain", d)}
											>
												<XIcon />
											</Button>
										{/if}
									</li>
								{/each}
							</ul>
						{/if}
						{#if canEdit}
							<form class="flex items-center gap-2" onsubmit={addDomain}>
								<Input bind:value={newDomain} placeholder="example.com" class="h-7 text-xs" aria-label="Domain to mute" />
								<Button type="submit" variant="outline" size="xs" disabled={!newDomain.trim()}>Add</Button>
							</form>
						{/if}
					</Popover.Content>
				</Popover.Root>
			{/if}
			<a
				href={`/dns/log?client=${encodeURIComponent(mac)}`}
				class="font-medium text-selected-foreground hover:underline">All queries →</a
			>
		</div>
	</footer>
</section>
