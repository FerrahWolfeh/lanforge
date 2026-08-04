<script lang="ts">
	import * as Dialog from "$lib/components/ui/dialog";
	import * as Field from "$lib/components/ui/field";
	import { Input } from "$lib/components/ui/input";
	import { Button } from "$lib/components/ui/button";
	import { Badge } from "$lib/components/ui/badge";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import SearchIcon from "@lucide/svelte/icons/search";
	import CheckCircle2Icon from "@lucide/svelte/icons/check-circle-2";
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

	const recordTypes = ["A", "AAAA", "CNAME", "MX", "TXT", "PTR", "NS", "SRV"];

	async function handleDigQuery(e: SubmitEvent) {
		e.preventDefault();
		if (!digDomain.trim()) return;
		digLoading = true;
		digResult = null;
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
									"rounded border px-2 py-1 font-mono text-xs font-medium transition-colors",
									digRecordType === rtype
										? "bg-primary text-primary-foreground border-primary"
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

		<!-- Dig Query Output Result Box -->
		{#if digResult}
			<div
				class="flex flex-col gap-2 rounded-lg border border-border/60 bg-muted/20 p-3 font-mono text-[11px] mt-1"
			>
				<div
					class="flex items-center justify-between border-b border-border/40 pb-1.5 font-sans"
				>
					<span
						class="font-semibold text-emerald-400 flex items-center gap-1"
					>
						<CheckCircle2Icon class="size-3.5" />
						Query Resolved
					</span>
					<Badge variant="outline" class="font-mono text-[10px]"
						>{digRecordType}</Badge
					>
				</div>

				<pre
					class="whitespace-pre-wrap break-all text-muted-foreground overflow-auto max-h-52 text-[11px] font-mono leading-relaxed">
{JSON.stringify(digResult, null, 2)}
				</pre>
			</div>
		{/if}
	</Dialog.Content>
</Dialog.Root>
