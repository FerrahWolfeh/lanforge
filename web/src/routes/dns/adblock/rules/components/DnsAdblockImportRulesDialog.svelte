<script lang="ts">
	import * as Dialog from "$lib/components/ui/dialog";
	import { Button } from "$lib/components/ui/button";
	import { Label } from "$lib/components/ui/label";
	import FileTextIcon from "@lucide/svelte/icons/file-text";
	import { toast } from "svelte-sonner";
	import { dnsAllow, dnsBlock } from "$lib/api/client";

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

	async function handleImport(e: Event) {
		e.preventDefault();
		const lines = rawText
			.split("\n")
			.map((l) => l.trim().toLowerCase().replace(/\.$/, ""))
			.filter((l) => l.length > 0 && !l.startsWith("#"));

		if (lines.length === 0) {
			toast.error("Please enter at least one valid domain");
			return;
		}

		importing = true;
		let successCount = 0;
		let failCount = 0;

		for (const domain of lines) {
			try {
				if (action === "allow") {
					await dnsAllow(domain);
				} else {
					await dnsBlock(domain);
				}
				successCount += 1;
			} catch {
				failCount += 1;
			}
		}

		if (successCount > 0) {
			toast.success(`Successfully imported ${successCount} domain(s)`);
		}
		if (failCount > 0) {
			toast.error(`Failed to import ${failCount} domain(s)`);
		}

		rawText = "";
		open = false;
		importing = false;
		onImported();
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
					Bulk Import Domains ({action === "allow" ? "Allowlist" : "Blocklist"})
				</Dialog.Title>
			</div>
			<Dialog.Description class="text-xs">
				Paste one domain per line. Lines beginning with '#' will be ignored.
			</Dialog.Description>
		</Dialog.Header>

		<form onsubmit={handleImport} class="flex flex-col gap-4 py-2">
			<div class="flex flex-col gap-1.5">
				<Label for="domains-textarea" class="text-xs font-semibold">Domains</Label>
				<textarea
					id="domains-textarea"
					placeholder="domain1.com&#10;sub.domain2.net&#10;# comment"
					bind:value={rawText}
					required
					rows={8}
					class="w-full rounded-md border border-input bg-transparent px-3 py-2 text-xs font-mono shadow-xs focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-ring"
				></textarea>
			</div>

			<Dialog.Footer class="pt-2">
				<Button
					type="button"
					variant="outline"
					size="sm"
					onclick={() => (open = false)}
					disabled={importing}
				>
					Cancel
				</Button>
				<Button type="submit" size="sm" disabled={importing}>
					{#if importing}
						Importing...
					{:else}
						Import Domains
					{/if}
				</Button>
			</Dialog.Footer>
		</form>
	</Dialog.Content>
</Dialog.Root>
