<script lang="ts">
	import * as Dialog from "$lib/components/ui/dialog";
	import { Button } from "$lib/components/ui/button";
	import { Badge } from "$lib/components/ui/badge";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import CheckIcon from "@lucide/svelte/icons/check";
	import ShieldAlertIcon from "@lucide/svelte/icons/shield-alert";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import SearchIcon from "@lucide/svelte/icons/search";
	import ArrowRightLeftIcon from "@lucide/svelte/icons/arrow-right-left";
	import ClockIcon from "@lucide/svelte/icons/clock";
	import LaptopIcon from "@lucide/svelte/icons/laptop";
	import GaugeIcon from "@lucide/svelte/icons/gauge";
	import { toast } from "svelte-sonner";
	import { dnsBlock, dnsAllow, dnsQuery } from "$lib/api/client";
	import type { DnsQueryLogEntry } from "$lib/api/types";

	let {
		open = $bindable(false),
		entry = null,
		onAddRewrite = (domain: string, target: string) => {},
	}: {
		open: boolean;
		entry: DnsQueryLogEntry | null;
		onAddRewrite?: (domain: string, target: string) => void;
	} = $props();

	let copiedField = $state<string | null>(null);
	let actionLoading = $state(false);
	let testQueryResult = $state<string | null>(null);
	let testingQuery = $state(false);

	function cleanDomain(raw: string): string {
		if (!raw) return "";
		return raw.trim().replace(/\.$/, "");
	}

	function cleanAnswer(raw?: string | null): string {
		if (!raw) return "—";
		return raw
			.replace(/^"|"$/g, "")
			.replace(/^(A|AAAA|CNAME|PTR|NS)\((.*)\)$/, "$2")
			.trim()
			.replace(/\.$/, "");
	}

	function formatLatency(us: number): string {
		if (us === 0) return "0 ms";
		if (us < 1000) return `${us} µs`;
		return `${(us / 1000).toFixed(2)} ms`;
	}

	function formatTimestamp(ts: number): string {
		if (!ts) return "—";
		const ms = ts < 1e11 ? ts * 1000 : ts;
		const date = new Date(ms);
		return date.toLocaleString(undefined, {
			year: "numeric",
			month: "2-digit",
			day: "2-digit",
			hour: "2-digit",
			minute: "2-digit",
			second: "2-digit",
			hour12: false,
		});
	}

	async function copyToClipboard(text: string, field: string) {
		try {
			await navigator.clipboard.writeText(text);
			copiedField = field;
			toast.success(`Copied ${field} to clipboard`);
			setTimeout(() => {
				copiedField = null;
			}, 2000);
		} catch {
			toast.error("Failed to copy");
		}
	}

	async function handleTestQuery() {
		if (!entry) return;
		testingQuery = true;
		testQueryResult = null;
		try {
			const res = await dnsQuery(cleanDomain(entry.domain), entry.qtype);
			testQueryResult = JSON.stringify(res, null, 2);
			toast.success("Diagnostic query test executed");
		} catch (err: any) {
			testQueryResult = `Error: ${err?.message ?? "Query failed"}`;
			toast.error("Diagnostic query failed");
		} finally {
			testingQuery = false;
		}
	}

	async function handleBlockDomain() {
		if (!entry) return;
		actionLoading = true;
		const dom = cleanDomain(entry.domain);
		try {
			await dnsBlock(dom);
			toast.success(`Added ${dom} to adblock black list`);
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to block domain");
		} finally {
			actionLoading = false;
		}
	}

	async function handleAllowDomain() {
		if (!entry) return;
		actionLoading = true;
		const dom = cleanDomain(entry.domain);
		try {
			await dnsAllow(dom);
			toast.success(`Added ${dom} to allowlist`);
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to allow domain");
		} finally {
			actionLoading = false;
		}
	}

	function handleCreateRewrite() {
		if (!entry) return;
		const dom = cleanDomain(entry.domain);
		const target = cleanAnswer(entry.answer);
		onAddRewrite(
			dom,
			target !== "—" && target !== "no-data" ? target : "",
		);
		open = false;
	}

	const domainClean = $derived(entry ? cleanDomain(entry.domain) : "");
	const answerClean = $derived(entry ? cleanAnswer(entry.answer) : "");
	const clientLabel = $derived.by(() => {
		if (!entry) return "—";
		if (entry.src_hostname) return `${entry.src_hostname} (${entry.src_ip})`;
		return entry.src_ip;
	});
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="w-[95vw] max-w-lg sm:max-w-lg overflow-hidden border shadow-lg">
		<Dialog.Header class="space-y-1 min-w-0 pr-6">
			<div class="flex items-center gap-2 min-w-0">
				<Badge variant="outline" class="font-mono text-xs px-2 py-0.5 shrink-0">
					{entry?.qtype ?? "A"}
				</Badge>
				<Dialog.Title class="text-base font-semibold font-mono truncate min-w-0" title={domainClean}>
					{domainClean}
				</Dialog.Title>
			</div>
			<Dialog.Description class="text-xs">
				Detailed DNS query telemetry, client attribution, and quick actions.
			</Dialog.Description>
		</Dialog.Header>

		{#if entry}
			<div class="space-y-4 py-2 text-sm min-w-0">
				<!-- Query Metadata Grid -->
				<div class="grid grid-cols-1 gap-3 rounded-lg border p-3 bg-muted/20 min-w-0">
					<!-- Domain -->
					<div class="min-w-0">
						<span class="text-[11px] text-muted-foreground font-medium uppercase tracking-wider block">
							Requested Domain
						</span>
						<div class="flex items-start justify-between gap-2 mt-1 min-w-0">
							<span class="font-mono font-medium text-xs break-all text-foreground min-w-0 flex-1 leading-relaxed">
								{domainClean}
							</span>
							<Button
								variant="ghost"
								size="icon"
								class="h-6 w-6 shrink-0 mt-0.5"
								onclick={() => copyToClipboard(domainClean, "Domain Name")}
							>
								{#if copiedField === "Domain Name"}
									<CheckIcon class="h-3 w-3 text-emerald-500" />
								{:else}
									<CopyIcon class="h-3 w-3 text-muted-foreground" />
								{/if}
							</Button>
						</div>
					</div>

					<!-- Client Info -->
					<div class="min-w-0">
						<span class="text-[11px] text-muted-foreground font-medium uppercase tracking-wider block">
							Requesting Client
						</span>
						<div class="flex items-center justify-between gap-2 mt-1 min-w-0">
							<div class="flex items-center gap-1.5 font-mono text-xs text-foreground min-w-0 truncate">
								<LaptopIcon class="h-3.5 w-3.5 text-muted-foreground shrink-0" />
								<span class="truncate">{clientLabel}</span>
								{#if entry.src_mac}
									<Badge variant="secondary" class="text-[10px] font-mono px-1 py-0 shrink-0">
										{entry.src_mac}
									</Badge>
								{/if}
							</div>
							<Button
								variant="ghost"
								size="icon"
								class="h-6 w-6 shrink-0"
								onclick={() => copyToClipboard(entry.src_ip, "Client IP")}
							>
								{#if copiedField === "Client IP"}
									<CheckIcon class="h-3 w-3 text-emerald-500" />
								{:else}
									<CopyIcon class="h-3 w-3 text-muted-foreground" />
								{/if}
							</Button>
						</div>
					</div>

					<!-- Resolution Outcome / Answer -->
					<div class="min-w-0">
						<span class="text-[11px] text-muted-foreground font-medium uppercase tracking-wider block">
							Resolution Result / Answer
						</span>
						<div class="flex items-start justify-between gap-2 mt-1 min-w-0">
							<div class="flex flex-wrap items-center gap-2 min-w-0 flex-1">
								<Badge
									variant="outline"
									class="text-[11px] font-mono border font-medium uppercase shrink-0 {entry.result.toLowerCase().includes('block') ? 'bg-rose-500/10 text-rose-500 border-rose-500/20' : entry.cached ? 'bg-blue-500/10 text-blue-500 border-blue-500/20' : 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20'}"
								>
									{entry.result}
									{#if entry.cached}
										(Cached)
									{/if}
								</Badge>
								<span class="font-mono text-xs break-all text-foreground/90 leading-relaxed">
									{answerClean}
								</span>
							</div>
							{#if answerClean !== "—"}
								<Button
									variant="ghost"
									size="icon"
									class="h-6 w-6 shrink-0 mt-0.5"
									onclick={() => copyToClipboard(answerClean, "Answer")}
								>
									{#if copiedField === "Answer"}
										<CheckIcon class="h-3 w-3 text-emerald-500" />
									{:else}
										<CopyIcon class="h-3 w-3 text-muted-foreground" />
									{/if}
								</Button>
							{/if}
						</div>
					</div>

					<!-- Timing & Latency -->
					<div class="flex items-center justify-between gap-2 pt-2 border-t border-border/50 text-xs min-w-0">
						<div class="flex items-center gap-1.5 text-muted-foreground min-w-0">
							<ClockIcon class="h-3.5 w-3.5 shrink-0" />
							<span class="truncate font-mono">{formatTimestamp(entry.timestamp)}</span>
						</div>
						<div class="flex items-center gap-1.5 text-muted-foreground shrink-0">
							<GaugeIcon class="h-3.5 w-3.5 shrink-0" />
							<span class="font-mono font-medium text-foreground">
								{formatLatency(entry.upstream_us)}
							</span>
						</div>
					</div>
				</div>

				<!-- Quick Action Toolbar -->
				<div>
					<span class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider block mb-2">
						Quick Administrative Actions
					</span>
					<div class="grid grid-cols-2 sm:grid-cols-4 gap-2">
						<Button
							variant="outline"
							size="sm"
							class="h-8 text-xs justify-start gap-1.5"
							disabled={testingQuery}
							onclick={handleTestQuery}
						>
							<SearchIcon class="h-3.5 w-3.5 text-blue-500" />
							<span>Test Query</span>
						</Button>

						<Button
							variant="outline"
							size="sm"
							class="h-8 text-xs justify-start gap-1.5"
							disabled={actionLoading}
							onclick={handleBlockDomain}
						>
							<ShieldAlertIcon class="h-3.5 w-3.5 text-rose-500" />
							<span>Block</span>
						</Button>

						<Button
							variant="outline"
							size="sm"
							class="h-8 text-xs justify-start gap-1.5"
							disabled={actionLoading}
							onclick={handleAllowDomain}
						>
							<ShieldCheckIcon class="h-3.5 w-3.5 text-emerald-500" />
							<span>Allow</span>
						</Button>

						<Button
							variant="outline"
							size="sm"
							class="h-8 text-xs justify-start gap-1.5"
							onclick={handleCreateRewrite}
						>
							<ArrowRightLeftIcon class="h-3.5 w-3.5 text-amber-500" />
							<span>Rewrite</span>
						</Button>
					</div>
				</div>

				<!-- Test Query Output Drawer -->
				{#if testQueryResult}
					<div class="rounded-md bg-muted p-2 text-xs font-mono max-h-36 overflow-y-auto">
						<pre class="whitespace-pre-wrap break-all">{testQueryResult}</pre>
					</div>
				{/if}
			</div>
		{/if}

		<Dialog.Footer class="pt-2">
			<Button variant="secondary" size="sm" onclick={() => (open = false)}>
				Close
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
