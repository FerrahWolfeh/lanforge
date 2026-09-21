<script lang="ts">
	import * as Dialog from "$lib/components/ui/dialog";
	import * as Alert from "$lib/components/ui/alert";
	import { Button } from "$lib/components/ui/button";
	import CheckCircle2Icon from "@lucide/svelte/icons/check-circle-2";
	import AlertTriangleIcon from "@lucide/svelte/icons/alert-triangle";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import CheckIcon from "@lucide/svelte/icons/check";
	import { copyToClipboard } from "$lib/utils";
	import type { AuthToken } from "$lib/api/types";

	let {
		open = $bindable(false),
		token = null
	}: {
		open: boolean;
		token: AuthToken | null;
	} = $props();

	let hasCopied = $state(false);

	$effect(() => {
		if (open) {
			hasCopied = false;
		}
	});

	async function handleCopy() {
		if (token?.token) {
			const success = await copyToClipboard(token.token, "API Key");
			if (success) hasCopied = true;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="sm:max-w-lg rounded-2xl">
		<Dialog.Header>
			<Dialog.Title class="text-base font-bold text-foreground flex items-center gap-2">
				<CheckCircle2Icon class="size-5 text-emerald-500" />
				API Key Generated Successfully!
			</Dialog.Title>
			<Dialog.Description class="text-xs">
				Copy your key now. For security reasons, this secret cannot be viewed again.
			</Dialog.Description>
		</Dialog.Header>

		<div class="flex flex-col gap-4 py-2">
			<!-- Alert Callout -->
			<Alert.Root class="rounded-xl border-amber-500/30 bg-amber-500/10 text-amber-900 dark:text-amber-200">
				<AlertTriangleIcon class="size-4 text-amber-600 dark:text-amber-400" />
				<Alert.Title class="text-xs font-bold">Important Notice</Alert.Title>
				<Alert.Description class="text-[11px] leading-relaxed mt-0.5">
					Store this key in a secure place (such as a password vault or environment file). If you lose it, you will need to revoke it and generate a new one.
				</Alert.Description>
			</Alert.Root>

			<!-- Token Display Box -->
			<div class="flex flex-col gap-1.5">
				<span class="text-xs font-semibold text-foreground">Key Secret (Token):</span>
				<div class="flex items-center gap-2 p-3 rounded-xl bg-muted/60 border border-border/80">
					<span class="font-mono text-xs font-bold text-foreground break-all flex-1 select-all">
						{token?.token ?? ""}
					</span>
					<Button
						variant="secondary"
						size="sm"
						class="rounded-xl cursor-pointer shrink-0 text-xs"
						onclick={handleCopy}
					>
						{#if hasCopied}
							<CheckIcon data-icon="inline-start" class="text-emerald-500" />
							Copied
						{:else}
							<CopyIcon data-icon="inline-start" />
							Copy
						{/if}
					</Button>
				</div>
			</div>

			<!-- Quick Usage Snippet -->
			<div class="flex flex-col gap-1.5">
				<span class="text-[11px] font-semibold text-muted-foreground">How to authenticate requests:</span>
				<div class="p-2.5 rounded-xl bg-muted/30 border border-border/60 font-mono text-[11px] text-foreground break-all select-all">
					Authorization: Bearer {token?.token ?? "lf_ak_..."}
				</div>
			</div>
		</div>

		<Dialog.Footer class="pt-2">
			<Button
				variant="default"
				size="sm"
				class="rounded-xl cursor-pointer text-xs w-full sm:w-auto"
				onclick={() => (open = false)}
			>
				Done & Close
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
