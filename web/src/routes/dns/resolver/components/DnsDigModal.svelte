<script lang="ts">
	import * as Dialog from "$lib/components/ui/dialog";
	import * as Field from "$lib/components/ui/field";
	import { Input } from "$lib/components/ui/input";
	import { Button } from "$lib/components/ui/button";
	import { Badge } from "$lib/components/ui/badge";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import SearchIcon from "@lucide/svelte/icons/search";
	import CheckCircle2Icon from "@lucide/svelte/icons/check-circle-2";
	import ShieldAlertIcon from "@lucide/svelte/icons/shield-alert";
	import ClockIcon from "@lucide/svelte/icons/clock";
	import CodeIcon from "@lucide/svelte/icons/code";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import CheckIcon from "@lucide/svelte/icons/check";
	import { dnsQuery } from "$lib/api/client";
	import { toast } from "svelte-sonner";

	let {
		open = $bindable(false),
	}: {
		open?: boolean;
	} = $props();

	let digDomain = $state("");
	let digRecordType = $state("A");
	let digLoading = $state(false);
	let digResult = $state<any | null>(null);
	let showRawJson = $state(false);
	let copied = $state(false);

	const recordTypes = ["A", "AAAA", "CNAME", "MX", "TXT", "PTR", "NS", "SRV"];

	let prevOpen = $state(false);

	$effect(() => {
		if (open && !prevOpen) {
			digDomain = "";
			digRecordType = "A";
			digLoading = false;
			digResult = null;
			showRawJson = false;
			copied = false;
		}
		prevOpen = open;
	});

	function getRecordTypeClass(kind: string): string {
		switch (kind.toUpperCase()) {
			case "A":
				return "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30";
			case "AAAA":
				return "bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/30";
			case "CNAME":
				return "bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30";
			case "MX":
				return "bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/30";
			case "TXT":
				return "bg-sky-500/10 text-sky-600 dark:text-sky-400 border-sky-500/30";
			case "PTR":
				return "bg-teal-500/10 text-teal-600 dark:text-teal-400 border-teal-500/30";
			default:
				return "bg-muted text-muted-foreground border-border";
		}
	}

	async function handleDigQuery(e: SubmitEvent) {
		e.preventDefault();
		if (!digDomain.trim()) return;
		digLoading = true;
		digResult = null;
		showRawJson = false;
		try {
			const res = await dnsQuery(digDomain.trim(), digRecordType);
			digResult = res;
			toast.success(`DNS ${digRecordType} lookup completed`);
		} catch (err: any) {
			toast.error(`DNS lookup failed: ${err.message || "Unknown error"}`);
		} finally {
			digLoading = false;
		}
	}

	function copyResult() {
		if (!digResult) return;
		navigator.clipboard.writeText(JSON.stringify(digResult, null, 2));
		copied = true;
		toast.success("Query output copied to clipboard");
		setTimeout(() => (copied = false), 2000);
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="sm:max-w-lg">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				<ZapIcon class="size-5 text-amber-400" />
				<span>Interactive DNS Dig Lookup</span>
			</Dialog.Title>
		</Dialog.Header>

		<form onsubmit={handleDigQuery} class="py-2 flex flex-col gap-4">
			<Field.FieldGroup class="gap-3">
				<Field.Field>
					<Field.FieldLabel for="modal-dig-domain"
						>Domain Name *</Field.FieldLabel
					>
					<div class="relative">
						<SearchIcon
							class="text-muted-foreground absolute left-3 top-1/2 size-4 -translate-y-1/2"
						/>
						<Input
							id="modal-dig-domain"
							placeholder="e.g. google.com or lanforge.local"
							class="pl-9 text-xs font-mono"
							bind:value={digDomain}
							required
						/>
					</div>
				</Field.Field>

				<Field.Field>
					<Field.FieldLabel for="modal-dig-type"
						>Record Type</Field.FieldLabel
					>
					<div class="grid grid-cols-4 gap-1.5">
						{#each recordTypes as rtype (rtype)}
							<button
								type="button"
								class={[
									"rounded border px-2 py-1 font-mono text-xs font-medium transition-colors cursor-pointer",
									digRecordType === rtype
										? "bg-primary text-primary-foreground border-primary shadow-xs"
										: "bg-muted/40 border-border text-muted-foreground hover:text-foreground",
								].join(" ")}
								onclick={() => (digRecordType = rtype)}
							>
								{rtype}
							</button>
						{/each}
					</div>
				</Field.Field>

				<Button
					type="submit"
					size="sm"
					class="w-full mt-1"
					disabled={digLoading}
				>
					{#if digLoading}
						<span
							class="size-3.5 animate-spin rounded-full border-2 border-current border-t-transparent mr-1"
						></span>
						Querying...
					{:else}
						<ZapIcon data-icon="inline-start" />
						Execute DNS Lookup
					{/if}
				</Button>
			</Field.FieldGroup>
		</form>

		<!-- Dig Query Formatted Output -->
		{#if digResult}
			{@const isBlocked = digResult.result === "Blocked" || digResult.result === "CachedBlock"}
			{@const records = Array.isArray(digResult.records) ? digResult.records : []}

			<div class="flex flex-col gap-3 rounded-xl border border-border/70 bg-card p-3.5 shadow-sm mt-1">
				<!-- Header Status -->
				<div class="flex flex-wrap items-center justify-between gap-2 border-b border-border/50 pb-2.5">
					<div class="flex items-center gap-2">
						{#if isBlocked}
							<div class="flex size-6 items-center justify-center rounded-full bg-rose-500/15 text-rose-500">
								<ShieldAlertIcon class="size-3.5" />
							</div>
							<span class="font-semibold text-rose-500 text-xs">Sinkholed (Blocked)</span>
						{:else}
							<div class="flex size-6 items-center justify-center rounded-full bg-emerald-500/15 text-emerald-500">
								<CheckCircle2Icon class="size-3.5" />
							</div>
							<span class="font-semibold text-foreground text-xs">Resolution Successful</span>
						{/if}
					</div>

					<div class="flex items-center gap-1.5 font-mono text-[11px]">
						<Badge variant="outline" class="h-5 px-1.5 font-mono text-[10px] gap-1">
							<ClockIcon class="size-2.5 text-muted-foreground" />
							{digResult.latency_ms ?? 0}ms
						</Badge>
						<Badge
							variant="outline"
							class={digResult.authoritative
								? "h-5 px-1.5 border-emerald-500/30 text-emerald-500 bg-emerald-500/5 text-[10px]"
								: "h-5 px-1.5 text-muted-foreground text-[10px]"}
						>
							{digResult.authoritative ? "Authoritative" : "Non-Authoritative"}
						</Badge>
						<Badge variant="secondary" class="h-5 px-1.5 text-[10px]">
							{digResult.result || "Resolved"}
						</Badge>
					</div>
				</div>

				<!-- Blocked Warning -->
				{#if isBlocked}
					<div class="rounded-lg border border-rose-500/25 bg-rose-500/10 p-2.5 text-xs text-rose-600 dark:text-rose-400">
						<p class="font-medium">Domain blocked by Lanforge Adblock.</p>
						<p class="text-[11px] opacity-80 mt-0.5">Queries to this domain are intercepted and resolved to 0.0.0.0 or NXDOMAIN by active blocklist rules.</p>
					</div>
				{/if}

				<!-- Answers List -->
				{#if records.length > 0}
					<div class="flex flex-col gap-1.5">
						<span class="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
							Answer Section ({records.length} {records.length === 1 ? "record" : "records"})
						</span>
						<div class="flex flex-col divide-y divide-border/40 rounded-lg border bg-muted/20 overflow-hidden">
							{#each records as record}
								<div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-2.5 font-mono text-xs hover:bg-muted/30 transition-colors">
									<div class="flex items-center gap-2 min-w-0">
										<Badge variant="outline" class={["text-[10px] font-bold px-1.5 py-0 h-5 shrink-0", getRecordTypeClass(record.kind || digRecordType)].join(" ")}>
											{record.kind || digRecordType}
										</Badge>
										<span class="text-foreground font-semibold truncate select-all">{record.data}</span>
									</div>
									<div class="flex items-center gap-3 text-[11px] text-muted-foreground shrink-0 justify-between sm:justify-end">
										<span class="text-xs text-muted-foreground truncate hidden md:inline">{record.name}</span>
										<span class="rounded bg-muted px-1.5 py-0.5 text-[10px]">TTL {record.ttl ?? 0}s</span>
									</div>
								</div>
							{/each}
						</div>
					</div>
				{:else if !isBlocked}
					<div class="rounded-lg border border-dashed p-4 text-center text-xs text-muted-foreground">
						No answer records returned for this query (NXDOMAIN or empty response).
					</div>
				{/if}

				<!-- Actions / Raw Toggle -->
				<div class="flex items-center justify-between pt-1 text-xs">
					<Button
						variant="ghost"
						size="sm"
						class="h-7 text-xs gap-1.5 text-muted-foreground hover:text-foreground"
						onclick={() => (showRawJson = !showRawJson)}
					>
						<CodeIcon class="size-3.5" />
						{showRawJson ? "Hide Raw JSON" : "Show Raw JSON"}
					</Button>

					<Button
						variant="ghost"
						size="sm"
						class="h-7 text-xs gap-1.5 text-muted-foreground hover:text-foreground"
						onclick={copyResult}
					>
						{#if copied}
							<CheckIcon class="size-3 text-emerald-400" />
							<span class="text-emerald-400">Copied</span>
						{:else}
							<CopyIcon class="size-3" />
							<span>Copy JSON</span>
						{/if}
					</Button>
				</div>

				<!-- Collapsible Raw JSON -->
				{#if showRawJson}
					<pre class="rounded-lg bg-muted/60 border p-3 font-mono text-[11px] text-foreground overflow-auto max-h-48 whitespace-pre-wrap break-all leading-relaxed select-all"><code>{JSON.stringify(digResult, null, 2)}</code></pre>
				{/if}
			</div>
		{/if}
	</Dialog.Content>
</Dialog.Root>
