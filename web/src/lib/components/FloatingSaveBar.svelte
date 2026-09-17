<script lang="ts">
	import { fly } from "svelte/transition";
	import { cubicOut } from "svelte/easing";
	import { Portal } from "bits-ui";
	import { Button } from "$lib/components/ui/button";
	import RotateCcwIcon from "@lucide/svelte/icons/rotate-ccw";
	import SaveIcon from "@lucide/svelte/icons/save";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import type { Component, Snippet } from "svelte";

	interface Props {
		show: boolean;
		count?: number;
		saving?: boolean;
		disabled?: boolean;
		title?: string;
		description?: string;
		saveLabel?: string;
		savingLabel?: string;
		discardLabel?: string;
		saveIcon?: Component<Record<string, unknown>>;
		onDiscard: () => void;
		onSave: () => void;
		customActions?: Snippet;
	}

	let {
		show,
		count = 0,
		saving = false,
		disabled = false,
		title = "",
		description = "Review and apply to commit new parameters to the daemon",
		saveLabel = "Save & Apply",
		savingLabel = "Saving...",
		discardLabel = "Discard",
		saveIcon: CustomSaveIcon,
		onDiscard,
		onSave,
		customActions,
	}: Props = $props();

	const displayTitle = $derived(
		title ||
		(count > 0
			? `${count} unsaved change${count === 1 ? "" : "s"}`
			: "Unsaved Changes")
	);
</script>

{#if show}
	<Portal>
		<div
			transition:fly={{ y: 24, duration: 220, easing: cubicOut }}
			class="fixed bottom-4 left-1/2 -translate-x-1/2 z-50 flex items-center justify-between p-3 sm:p-3.5 rounded-xl border bg-card/95 backdrop-blur-md shadow-2xl border-primary/40 gap-4 w-[92vw] max-w-3xl pointer-events-auto"
		>
			<div class="flex items-center gap-2.5 min-w-0">
				<span class="relative flex size-2.5 shrink-0">
					<span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-75"></span>
					<span class="relative inline-flex rounded-full size-2.5 bg-amber-500"></span>
				</span>
				<div class="flex flex-col sm:flex-row sm:items-center sm:gap-2 truncate">
					<span class="text-xs font-semibold text-foreground truncate">
						{displayTitle}
					</span>
					{#if description}
						<span class="text-[11px] text-muted-foreground hidden sm:inline truncate">
							{description}
						</span>
					{/if}
				</div>
			</div>

			{#if customActions}
				{@render customActions()}
			{:else}
				<div class="flex items-center gap-2 shrink-0">
					<Button
						variant="outline"
						size="sm"
						onclick={onDiscard}
						disabled={saving || disabled}
						class="h-8 text-xs transition-transform duration-150 active:scale-95 transform-gpu cursor-pointer"
					>
						<RotateCcwIcon class="size-3.5" data-icon="inline-start" />
						{discardLabel}
					</Button>

					<Button
						variant="default"
						size="sm"
						onclick={onSave}
						disabled={saving || disabled}
						class="h-8 text-xs shadow-xs transition-all duration-150 hover:shadow-primary/20 hover:shadow-md active:scale-95 transform-gpu cursor-pointer"
					>
						{#if saving}
							<RefreshCwIcon class="animate-spin size-3.5" data-icon="inline-start" />
							{savingLabel}
						{:else}
							{#if CustomSaveIcon}
								<CustomSaveIcon class="size-3.5" data-icon="inline-start" />
							{:else}
								<SaveIcon class="size-3.5" data-icon="inline-start" />
							{/if}
							{saveLabel}
						{/if}
					</Button>
				</div>
			{/if}
		</div>
	</Portal>
{/if}
