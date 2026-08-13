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
	import { toast } from "svelte-sonner";
	import { dnsBlock, dnsAllow, dnsQuery } from "$lib/api/client";
	import type { DnsCacheEntry } from "$lib/api/types";

	let {
		open = $bindable(false),
		entry = null,
		onAddRewrite = (domain: string, target: string) => {},
	}: {
		open: boolean;
		entry: DnsCacheEntry | null;
		onAddRewrite?: (domain: string, target: string) => void;
	} = $props();

	let copiedField = $state<string | null>(null);
	let actionLoading = $state(false);
	let testQueryResult = $state<string | null>(null);
	let testingQuery = $state(false);

	function cleanName(raw: string): string {
		if (!raw) return "";
		return raw.trim().replace(/\.$/, "");
	}

	function cleanData(raw: string): string {
		if (!raw) return "—";
		return raw
			.replace(/^"|"$/g, "")
			.replace(/^(A|AAAA|CNAME|PTR|NS)\((.*)\)$/, "$2")
			.trim()
			.replace(/\.$/, "");
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
			const res = await dnsQuery(cleanName(entry.name), entry.kind);
			testQueryResult = JSON.stringify(res, null, 2);
			toast.success("Query test executed successfully");
		} catch (err: any) {
			testQueryResult = `Error: ${err?.message ?? "Query failed"}`;
			toast.error("Query test failed");
		} finally {
			testingQuery = false;
		}
	}

	async function handleBlockDomain() {
		if (!entry) return;
		actionLoading = true;
		try {
			await dnsBlock(cleanName(entry.name));
			toast.success(
				`Added ${cleanName(entry.name)} to adblock black list`,
			);
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to block domain");
		} finally {
			actionLoading = false;
		}
	}

	async function handleAllowDomain() {
		if (!entry) return;
		actionLoading = true;
		try {
			await dnsAllow(cleanName(entry.name));
			toast.success(`Added ${cleanName(entry.name)} to allowlist`);
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to allow domain");
		} finally {
			actionLoading = false;
		}
	}

	function handleCreateRewrite() {
		if (!entry) return;
		const domain = cleanName(entry.name);
		const target = cleanData(entry.data);
		onAddRewrite(
			domain,
			target !== "no-data" && target !== "wire-error" ? target : "",
		);
		open = false;
	}

	const formattedName = $derived(entry ? cleanName(entry.name) : "");
	const formattedData = $derived(entry ? cleanData(entry.data) : "");
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="sm:max-w-xl">
		<Dialog.Header class="space-y-1">
			<div class="flex items-center gap-2">
				<Badge variant="outline" class="font-mono text-xs px-2 py-0.5">
					{entry?.kind ?? "DNS"}
				</Badge>
				<Dialog.Title
					class="text-base font-semibold font-mono truncate"
				>
					{formattedName}
				</Dialog.Title>
			</div>
			<Dialog.Description class="text-xs">
				In-memory cache record inspection and quick administrative
				controls.
			</Dialog.Description>
		</Dialog.Header>

		{#if entry}
			<div class="space-y-4 py-2 text-sm">
				<!-- Record Overview Grid -->
				<div
					class="grid grid-cols-1 gap-3 rounded-lg border p-3 bg-muted/20"
				>
					<!-- Domain -->
					<div>
						<span
							class="text-xs text-muted-foreground font-medium uppercase tracking-wider"
						>
							Domain Name
						</span>
						<div class="flex items-center justify-between mt-1">
							<span
								class="font-mono font-medium text-xs break-all text-foreground"
							>
								{formattedName}
							</span>
							<Button
								variant="ghost"
								size="icon"
								class="h-6 w-6 shrink-0"
								onclick={() =>
									copyToClipboard(
										formattedName,
										"Domain Name",
									)}
							>
								{#if copiedField === "Domain Name"}
									<CheckIcon
										class="h-3 w-3 text-emerald-500"
									/>
								{:else}
									<CopyIcon
										class="h-3 w-3 text-muted-foreground"
									/>
								{/if}
							</Button>
						</div>
					</div>

					<!-- Resolved Value -->
					<div>
						<span
							class="text-xs text-muted-foreground font-medium uppercase tracking-wider"
						>
							Resolved Target / Answer
						</span>
						<div class="flex items-center justify-between mt-1">
							<span
								class="font-mono text-xs break-all text-foreground/90"
							>
								{formattedData}
							</span>
							<Button
								variant="ghost"
								size="icon"
								class="h-6 w-6 shrink-0"
								onclick={() =>
									copyToClipboard(
										formattedData,
										"Answer Data",
									)}
							>
								{#if copiedField === "Answer Data"}
									<CheckIcon
										class="h-3 w-3 text-emerald-500"
									/>
								{:else}
									<CopyIcon
										class="h-3 w-3 text-muted-foreground"
									/>
								{/if}
							</Button>
						</div>
					</div>

					<!-- TTL Meta -->
					<div
						class="flex items-center justify-between pt-1 border-t border-border/50 text-xs"
					>
						<div
							class="flex items-center gap-1.5 text-muted-foreground"
						>
							<ClockIcon class="h-3.5 w-3.5" />
							<span>Expires in:</span>
						</div>
						<span class="font-mono font-medium text-foreground">
							{entry.expires_in_secs} seconds
						</span>
					</div>
				</div>

				<!-- Quick Action Toolbar -->
				<div>
					<span
						class="text-xs font-medium text-muted-foreground uppercase tracking-wider block mb-2"
					>
						Quick Actions
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
							<ShieldAlertIcon
								class="h-3.5 w-3.5 text-rose-500"
							/>
							<span>Block</span>
						</Button>

						<Button
							variant="outline"
							size="sm"
							class="h-8 text-xs justify-start gap-1.5"
							disabled={actionLoading}
							onclick={handleAllowDomain}
						>
							<ShieldCheckIcon
								class="h-3.5 w-3.5 text-emerald-500"
							/>
							<span>Allow</span>
						</Button>

						<Button
							variant="outline"
							size="sm"
							class="h-8 text-xs justify-start gap-1.5"
							onclick={handleCreateRewrite}
						>
							<ArrowRightLeftIcon
								class="h-3.5 w-3.5 text-amber-500"
							/>
							<span>Rewrite</span>
						</Button>
					</div>
				</div>

				<!-- Test Query Output Drawer -->
				{#if testQueryResult}
					<div
						class="rounded-md bg-muted p-2 text-xs font-mono max-h-36 overflow-y-auto"
					>
						<pre
							class="whitespace-pre-wrap break-all">{testQueryResult}</pre>
					</div>
				{/if}
			</div>
		{/if}

		<Dialog.Footer class="pt-2">
			<Button
				variant="secondary"
				size="sm"
				onclick={() => (open = false)}
			>
				Close
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
