<script lang="ts">
	import * as Dialog from "$lib/components/ui/dialog";
	import * as Select from "$lib/components/ui/select";
	import { Input } from "$lib/components/ui/input";
	import { Button } from "$lib/components/ui/button";
	import { Label } from "$lib/components/ui/label";
	import LinkIcon from "@lucide/svelte/icons/link";
	import { toast } from "svelte-sonner";
	import { dnsAdblockUrlAdd } from "$lib/api/client";
	import type { DnsAdblockUrlEntry } from "$lib/api/types";

	let {
		open = $bindable(false),
		onAdded = () => {},
	}: {
		open?: boolean;
		onAdded?: () => void;
	} = $props();

	let url = $state("");
	let kind = $state<"blocklist" | "allowlist">("blocklist");
	let submitting = $state(false);

	async function handleSubmit(e: Event) {
		e.preventDefault();
		const trimmedUrl = url.trim();
		if (!trimmedUrl) {
			toast.error("Please enter a valid list URL");
			return;
		}

		if (!trimmedUrl.startsWith("http://") && !trimmedUrl.startsWith("https://")) {
			toast.error("URL must begin with http:// or https://");
			return;
		}

		submitting = true;
		try {
			await dnsAdblockUrlAdd({
				url: trimmedUrl,
				kind,
			});
			toast.success(`Added ${kind}: ${trimmedUrl}`);
			url = "";
			open = false;
			onAdded();
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to add source URL");
		} finally {
			submitting = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="sm:max-w-md">
		<Dialog.Header>
			<div class="flex items-center gap-2">
				<div class="p-2 rounded-lg bg-primary/10 text-primary">
					<LinkIcon class="size-4" />
				</div>
				<Dialog.Title>Add Filter List URL</Dialog.Title>
			</div>
			<Dialog.Description class="text-xs">
				Enter a remote URL containing host-formatted rules (0.0.0.0 domain.com) or plain domain lists.
			</Dialog.Description>
		</Dialog.Header>

		<form onsubmit={handleSubmit} class="flex flex-col gap-4 py-2">
			<!-- Source URL -->
			<div class="flex flex-col gap-1.5">
				<Label for="source-url" class="text-xs font-semibold">List Source URL</Label>
				<Input
					id="source-url"
					placeholder="https://example.com/hosts.txt"
					bind:value={url}
					required
					class="font-mono text-xs"
				/>
				<p class="text-[11px] text-muted-foreground">
					Must be publicly accessible via HTTP/HTTPS.
				</p>
			</div>

			<!-- List Type -->
			<div class="flex flex-col gap-1.5">
				<Label for="source-kind" class="text-xs font-semibold">List Purpose</Label>
				<Select.Root
					type="single"
					value={kind}
					onValueChange={(val) => {
						if (val === "blocklist" || val === "allowlist") kind = val;
					}}
				>
					<Select.Trigger class="w-full text-xs">
						{kind === "blocklist" ? "Blocklist (Sinkhole domains)" : "Allowlist (Whitelist exceptions)"}
					</Select.Trigger>
					<Select.Content>
						<Select.Item value="blocklist" class="text-xs">
							Blocklist (Sinkhole domains)
						</Select.Item>
						<Select.Item value="allowlist" class="text-xs">
							Allowlist (Whitelist exceptions)
						</Select.Item>
					</Select.Content>
				</Select.Root>
			</div>

			<Dialog.Footer class="pt-2">
				<Button
					type="button"
					variant="outline"
					size="sm"
					onclick={() => (open = false)}
					disabled={submitting}
				>
					Cancel
				</Button>
				<Button type="submit" size="sm" disabled={submitting}>
					{#if submitting}
						Adding...
					{:else}
						Add Source
					{/if}
				</Button>
			</Dialog.Footer>
		</form>
	</Dialog.Content>
</Dialog.Root>
