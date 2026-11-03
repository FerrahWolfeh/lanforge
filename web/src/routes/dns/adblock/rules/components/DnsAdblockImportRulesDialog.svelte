<script lang="ts">
	import * as Dialog from "$lib/components/ui/dialog";
	import { Button } from "$lib/components/ui/button";
	import { Label } from "$lib/components/ui/label";
	import FileTextIcon from "@lucide/svelte/icons/file-text";
	import { toast } from "svelte-sonner";
	import { dnsAdblockRulesImport } from "$lib/api/client";
	import type { AdblockRulesImport } from "$lib/api/types";

	let {
		open = $bindable(false),
		action = "allow",
		onImported = () => {},
	}: {
		open?: boolean;
		action?: "allow" | "block";
		onImported?: () => void;
	} = $props();

	let rawText = $state("");
	let importing = $state(false);
	/** The last import's outcome, kept open when some lines were skipped or rejected. */
	let report = $state<AdblockRulesImport | null>(null);

	$effect(() => {
		if (!open) report = null;
	});

	function summary(r: AdblockRulesImport): string {
		const parts = [`${r.added.toLocaleString()} added`];
		if (r.unchanged) parts.push(`${r.unchanged.toLocaleString()} already present`);
		if (r.conflicts) parts.push(`${r.conflicts.toLocaleString()} kept as opposite rule`);
		if (r.rejected_total) parts.push(`${r.rejected_total.toLocaleString()} rejected`);
		return parts.join(", ");
	}

	async function handleImport(e: Event) {
		e.preventDefault();
		if (!rawText.trim()) {
			toast.error("Paste at least one domain or rule");
			return;
		}
		importing = true;
		try {
			const r = await dnsAdblockRulesImport(rawText, action);
			toast.success(summary(r));
			if (r.added && !r.saved) {
				toast.warning("Applied in memory only: the configuration file is read-only or not set");
			}
			onImported();
			if (r.rejected_total || r.conflicts) {
				report = r;
			} else {
				rawText = "";
				open = false;
			}
		} catch (err) {
			toast.error(err instanceof Error ? err.message : "Import failed");
		} finally {
			importing = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="sm:max-w-lg">
		<Dialog.Header>
			<div class="flex items-center gap-2">
				<div class="p-2 rounded-lg bg-primary/10 text-primary">
					<FileTextIcon class="size-4" />
				</div>
				<Dialog.Title>
					Bulk Import Rules ({action === "allow" ? "Allowlist" : "Blocklist"})
				</Dialog.Title>
			</div>
			<Dialog.Description class="text-xs">
				Paste a list: one domain, rule (<code>||x^</code>, <code>@@||x^</code>) or hosts line per
				line. Lines starting with <code>#</code> or <code>!</code> are ignored. A rule whose
				opposite already exists is skipped, so your exceptions are kept.
			</Dialog.Description>
		</Dialog.Header>

		<form onsubmit={handleImport} class="flex flex-col gap-4 py-2">
			<div class="flex flex-col gap-1.5">
				<Label for="domains-textarea" class="text-xs font-semibold">Rules</Label>
				<textarea
					id="domains-textarea"
					placeholder="domain1.com&#10;sub.domain2.net&#10;# comment"
					bind:value={rawText}
					required
					rows={10}
					spellcheck="false"
					class="w-full rounded-md border border-input bg-transparent px-3 py-2 text-xs font-mono shadow-xs focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-ring"
				></textarea>
			</div>

			{#if report}
				<div class="flex flex-col gap-1.5 rounded-md border border-border/60 bg-muted/30 p-3 text-xs">
					<p class="font-medium">{summary(report)}</p>
					{#if report.rejected.length > 0}
						<ul class="max-h-40 overflow-y-auto font-mono text-[11px] text-muted-foreground">
							{#each report.rejected as r (r.line)}
								<li class="truncate" title={r.reason}>
									<span class="text-destructive">line {r.line}:</span>
									{r.text} — {r.reason}
								</li>
							{/each}
						</ul>
						{#if report.rejected_total > report.rejected.length}
							<p class="text-muted-foreground">
								…and {(report.rejected_total - report.rejected.length).toLocaleString()} more
							</p>
						{/if}
					{/if}
				</div>
			{/if}

			<Dialog.Footer class="pt-2">
				<Button
					type="button"
					variant="outline"
					size="sm"
					onclick={() => (open = false)}
					disabled={importing}
				>
					{report ? "Close" : "Cancel"}
				</Button>
				<Button type="submit" size="sm" disabled={importing}>
					{#if importing}
						Importing...
					{:else}
						Import
					{/if}
				</Button>
			</Dialog.Footer>
		</form>
	</Dialog.Content>
</Dialog.Root>
