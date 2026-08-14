<script lang="ts">
	import * as Dialog from "$lib/components/ui/dialog";
	import { Button } from "$lib/components/ui/button";
	import { Label } from "$lib/components/ui/label";
	import FileUpIcon from "@lucide/svelte/icons/file-up";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import { toast } from "svelte-sonner";
	import { dnsRewriteImport } from "$lib/api/client";
	import type { RewriteRule } from "$lib/api/types";

	let {
		open = $bindable(false),
		onImportSuccess = () => {},
	}: {
		open: boolean;
		onImportSuccess?: () => void;
	} = $props();

	let jsonText = $state("");
	let importing = $state(false);

	async function handleFileUpload(e: Event) {
		const target = e.target as HTMLInputElement;
		const file = target.files?.[0];
		if (!file) return;

		try {
			const content = await file.text();
			jsonText = content;
			toast.success(`Loaded ${file.name}`);
		} catch {
			toast.error("Failed to read JSON file");
		}
	}

	async function handleImport() {
		const raw = jsonText.trim();
		if (!raw) {
			toast.error("Please paste JSON rules or select a file to import");
			return;
		}

		try {
			const parsed = JSON.parse(raw);
			const rulesList: RewriteRule[] = Array.isArray(parsed)
				? parsed
				: Array.isArray(parsed.rules)
					? parsed.rules
					: [];

			if (rulesList.length === 0) {
				toast.error("Invalid JSON format or empty rules array");
				return;
			}

			importing = true;
			await dnsRewriteImport(rulesList);
			toast.success(`Successfully imported ${rulesList.length} DNS rewrite rules`);
			open = false;
			onImportSuccess();
		} catch (err: any) {
			toast.error(err?.message ?? "JSON parse or import failed");
		} finally {
			importing = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="w-[95vw] max-w-lg sm:max-w-lg overflow-hidden border shadow-lg">
		<Dialog.Header class="space-y-1">
			<Dialog.Title class="text-base font-semibold flex items-center gap-2">
				<FileUpIcon class="h-5 w-5 text-primary" />
				Import DNS Rewrite Rules
			</Dialog.Title>
			<Dialog.Description class="text-xs">
				Bulk import DNS rewrite rules from an exported JSON configuration file.
			</Dialog.Description>
		</Dialog.Header>

		<div class="space-y-4 py-2 text-xs">
			<!-- File Upload Input -->
			<div class="space-y-1.5">
				<Label for="import-file" class="text-xs font-medium">Select JSON File</Label>
				<input
					id="import-file"
					type="file"
					accept=".json"
					onchange={handleFileUpload}
					class="block w-full text-xs text-muted-foreground file:mr-4 file:py-1.5 file:px-3 file:rounded-md file:border file:border-input file:bg-background file:text-xs file:font-medium hover:file:bg-accent hover:file:text-accent-foreground cursor-pointer"
				/>
			</div>

			<!-- Raw JSON Textarea -->
			<div class="space-y-1.5">
				<Label for="json-text" class="text-xs font-medium">Or Paste Raw JSON Rules</Label>
				<textarea
					id="json-text"
					rows={8}
					placeholder={`[\n  { "domain": "app.lan", "rtype": "A", "answer": "192.168.1.50" },\n  { "domain": "server.local", "rtype": "A", "answer": "dev:00:11:22:33:44:55" }\n]`}
					class="w-full rounded-md border border-input bg-muted/20 p-2.5 text-xs font-mono focus:outline-hidden focus:ring-1 focus:ring-ring"
					bind:value={jsonText}
				></textarea>
			</div>
		</div>

		<Dialog.Footer class="pt-2 gap-2 sm:gap-0">
			<Button variant="outline" size="sm" onclick={() => (open = false)} disabled={importing}>
				Cancel
			</Button>
			<Button size="sm" onclick={handleImport} disabled={importing} class="gap-2">
				{#if importing}
					<RefreshCwIcon class="h-4 w-4 animate-spin" />
					Importing...
				{:else}
					<FileUpIcon class="h-4 w-4" />
					Import Rules
				{/if}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
