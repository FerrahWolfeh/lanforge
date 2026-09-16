<script lang="ts">
	import * as Dialog from "$lib/components/ui/dialog";
	import * as Alert from "$lib/components/ui/alert";
	import { Button } from "$lib/components/ui/button";
	import { ScrollArea } from "$lib/components/ui/scroll-area";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { Separator } from "$lib/components/ui/separator";
	import { Spinner } from "$lib/components/ui/spinner";
	import AlertTriangleIcon from "@lucide/svelte/icons/alert-triangle";
	import CheckCircleIcon from "@lucide/svelte/icons/check-circle";
	import XCircleIcon from "@lucide/svelte/icons/x-circle";
	import { cn } from "$lib/utils";
	import type { FirewallValidationReport } from "$lib/api/types";

	let {
		open = $bindable(false),
		report,
		committing,
		rollbackSecsLeft,
		onConfirm,
		onAbort,
		onClose,
	}: {
		open: boolean;
		report: FirewallValidationReport | null;
		committing: boolean;
		rollbackSecsLeft: number | null;
		onConfirm: () => void;
		onAbort: () => void;
		onClose: () => void;
	} = $props();

	function diffLineKind(line: string): "add" | "remove" | "change" | "header" {
		if (line.startsWith("+")) return "add";
		if (line.startsWith("-")) return "remove";
		if (line.startsWith("~")) return "change";
		return "header";
	}

	function handleOpenChange(v: boolean) {
		if (!v) onClose();
		open = v;
	}
</script>

<Dialog.Root bind:open onOpenChange={handleOpenChange}>
	<Dialog.Content class="sm:max-w-xl w-[95vw] flex flex-col gap-0 p-0 overflow-hidden">
		<Dialog.Header class="px-6 pt-6 pb-4">
			<Dialog.Title class="flex items-center gap-2 text-base font-semibold">
				{#if report === null}
					<Skeleton class="size-5 rounded-full" />
					<Skeleton class="h-5 w-56" />
				{:else if report.valid}
					<CheckCircleIcon data-icon="inline-start" class="text-primary" />
					Review Firewall Changes
				{:else}
					<XCircleIcon data-icon="inline-start" class="text-destructive" />
					Review Firewall Changes
				{/if}
			</Dialog.Title>
			<Dialog.Description class="text-xs text-muted-foreground">
				Review pending changes and dry-run validation before committing rules.
			</Dialog.Description>
		</Dialog.Header>

		<Separator />

		<div class="flex flex-col gap-4 px-6 py-4 overflow-y-auto max-h-[60vh]">
			{#if report === null}
				<div class="flex flex-col gap-2">
					<Skeleton class="h-4 w-3/4" />
					<Skeleton class="h-4 w-full" />
					<Skeleton class="h-4 w-5/6" />
					<Skeleton class="h-4 w-2/3" />
					<Skeleton class="h-16 w-full mt-2 rounded-lg" />
				</div>
			{:else if !report.valid}
				{#if report.errors.length > 0}
					<Alert.Root variant="destructive">
						<XCircleIcon data-icon="inline-start" />
						<Alert.Title>Configuration contains validation errors</Alert.Title>
						<Alert.Description>
							<ul class="mt-1.5 flex flex-col gap-1 list-disc list-inside text-xs font-mono">
								{#each report.errors as err (err)}
									<li>{err}</li>
								{/each}
							</ul>
						</Alert.Description>
					</Alert.Root>
				{/if}

				{#if report.warnings.length > 0}
					<Alert.Root class="border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-400">
						<AlertTriangleIcon data-icon="inline-start" />
						<Alert.Title>Warnings</Alert.Title>
						<Alert.Description>
							<ul class="mt-1.5 flex flex-col gap-1 list-disc list-inside text-xs font-mono">
								{#each report.warnings as w (w)}
									<li>{w}</li>
								{/each}
							</ul>
						</Alert.Description>
					</Alert.Root>
				{/if}
			{:else}
				{#if report.warnings.length > 0}
					<Alert.Root class="border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-400">
						<AlertTriangleIcon data-icon="inline-start" />
						<Alert.Title>Warnings</Alert.Title>
						<Alert.Description>
							<ul class="mt-1.5 flex flex-col gap-1 list-disc list-inside text-xs font-mono">
								{#each report.warnings as w (w)}
									<li>{w}</li>
								{/each}
							</ul>
						</Alert.Description>
					</Alert.Root>
				{/if}

				{#if rollbackSecsLeft !== null}
					<div class="flex items-center gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2.5 text-xs font-medium text-amber-700 dark:text-amber-400">
						<AlertTriangleIcon class="size-4 shrink-0 text-amber-500" />
						<span>
							Auto-rollback active in
							<strong class="font-mono text-foreground font-bold">{rollbackSecsLeft}s</strong>
							— confirm connection to persist new rules permanently.
						</span>
					</div>
				{/if}

				{#if report.diff_summary.length > 0}
					<div class="flex flex-col gap-1.5">
						<p class="text-xs font-medium text-foreground">Diff Summary</p>
						<ScrollArea class="max-h-80 rounded-lg border border-border">
							<div class="bg-muted/50 p-3 font-mono text-xs">
								{#each report.diff_summary as line, i (i)}
									{@const kind = diffLineKind(line)}
									<div
										class={cn(
											"py-0.5 pl-2 border-l-2",
											kind === "add" && "text-emerald-600 dark:text-emerald-400 border-emerald-500",
											kind === "remove" && "text-destructive border-destructive",
											kind === "change" && "text-amber-600 dark:text-amber-400 border-amber-500",
											kind === "header" && "text-muted-foreground border-transparent pl-0 font-semibold",
										)}
									>
										{line}
									</div>
								{/each}
							</div>
						</ScrollArea>
					</div>
				{:else}
					<p class="text-xs text-muted-foreground italic">No rule diff detected.</p>
				{/if}
			{/if}
		</div>

		<Separator />

		<Dialog.Footer class="px-6 py-4 flex flex-row gap-2 justify-end">
			{#if report !== null && !report.valid}
				<Button variant="outline" onclick={onClose} disabled={committing}>Close</Button>
			{:else if report !== null && report.valid}
				<Button
					variant="outline"
					class="border-destructive text-destructive hover:bg-destructive/10 hover:text-destructive"
					onclick={onAbort}
					disabled={committing}
				>
					Abort
				</Button>
				<Button onclick={onConfirm} disabled={committing}>
					{#if committing}
						<Spinner data-icon="inline-start" />
						Applying…
					{:else}
						Commit & Apply
					{/if}
				</Button>
			{:else}
				<Button variant="outline" onclick={onClose} disabled>Close</Button>
			{/if}
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
