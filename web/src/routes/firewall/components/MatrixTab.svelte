<script lang="ts">
	import CheckIcon from '@lucide/svelte/icons/check';
	import XIcon from '@lucide/svelte/icons/x';
	import * as Tooltip from '$lib/components/ui/tooltip';
	import { Separator } from '$lib/components/ui/separator';
	import { cn } from '$lib/utils';
	import type { FirewallZone, ZoneForwarding } from '$lib/api/types';

	interface Props {
		zones: FirewallZone[];
		forwardings: ZoneForwarding[];
		highlightedZone: string | null;
		onUpdate: (forwardings: ZoneForwarding[]) => void;
	}

	let { zones, forwardings, highlightedZone, onUpdate }: Props = $props();

	function isAllowed(from: string, to: string): boolean {
		return forwardings.some((f) => f.from === from && f.to === to);
	}

	function isHighlighted(zoneName: string): boolean {
		return highlightedZone !== null && highlightedZone === zoneName;
	}

	function toggle(from: string, to: string) {
		if (isAllowed(from, to)) {
			onUpdate(forwardings.filter((f) => !(f.from === from && f.to === to)));
		} else {
			onUpdate([...forwardings, { from, to }]);
		}
	}
</script>

<div class="flex flex-col gap-4">
	<!-- Matrix table -->
	<div class="overflow-x-auto rounded-xl border border-border">
		<table class="min-w-full border-collapse text-sm">
			<!-- Header row -->
			<thead>
				<tr>
					<!-- Top-left empty corner cell -->
					<th
						class="border-b border-r border-border bg-muted/40 px-4 py-3 text-left"
						aria-label="Source / Destination Zone"
					>
						<span class="font-mono text-xs text-muted-foreground">src → dst</span>
					</th>
					{#each zones as zone (zone.name)}
						<th
							class={cn(
								'border-b border-r border-border px-4 py-3 text-center last:border-r-0',
								'transition-colors duration-150',
								isHighlighted(zone.name) ? 'bg-primary/5' : 'bg-muted/40'
							)}
						>
							<span class="font-mono text-xs font-semibold text-foreground">→ {zone.name}</span>
						</th>
					{/each}
				</tr>
			</thead>

			<!-- Body rows -->
			<tbody>
				{#each zones as fromZone (fromZone.name)}
					<tr class="group/row">
						<!-- Row header -->
						<td
							class={cn(
								'border-b border-r border-border px-4 py-3 last:border-b-0',
								'transition-colors duration-150',
								isHighlighted(fromZone.name) ? 'bg-primary/5' : 'bg-muted/20'
							)}
						>
							<span class="font-mono text-xs font-semibold text-foreground"
								>{fromZone.name} →</span
							>
						</td>

						{#each zones as toZone (toZone.name)}
							{@const isDiagonal = fromZone.name === toZone.name}
							{@const allowed = !isDiagonal && isAllowed(fromZone.name, toZone.name)}
							{@const rowHighlighted = isHighlighted(fromZone.name)}
							{@const colHighlighted = isHighlighted(toZone.name)}

							<td
								class={cn(
									'border-b border-r border-border p-2 text-center last:border-r-0',
									'transition-colors duration-150',
									isDiagonal && 'bg-muted/50',
									(rowHighlighted || colHighlighted) && !isDiagonal && 'bg-primary/5'
								)}
							>
								{#if isDiagonal}
									<span class="select-none text-muted-foreground font-mono" aria-label="Same zone">—</span>
								{:else}
									<Tooltip.Provider>
										<Tooltip.Root>
											<Tooltip.Trigger>
												{#snippet child({ props: tooltipProps })}
													<button
														{...tooltipProps}
														type="button"
														onclick={() => toggle(fromZone.name, toZone.name)}
														class={cn(
															'inline-flex cursor-pointer items-center gap-1 rounded-full border px-3 py-1 text-xs font-medium',
															'transition-all duration-150',
															'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1',
															allowed
																? 'border-emerald-500/30 bg-emerald-500/20 text-emerald-700 hover:bg-emerald-500/30 dark:text-emerald-400'
																: 'border-border bg-muted text-muted-foreground hover:bg-muted/80'
														)}
														aria-label={allowed
															? `Block forwarding from ${fromZone.name} to ${toZone.name}`
															: `Allow forwarding from ${fromZone.name} to ${toZone.name}`}
														aria-pressed={allowed}
													>
														{#if allowed}
															<CheckIcon data-icon="inline-start" />
															<span>Allowed</span>
														{:else}
															<XIcon data-icon="inline-start" />
															<span>Blocked</span>
														{/if}
													</button>
												{/snippet}
											</Tooltip.Trigger>
											<Tooltip.Portal>
												<Tooltip.Content side="top">
													{#if allowed}
														Click to <strong>block</strong> traffic from
														<code class="font-mono">{fromZone.name}</code> →
														<code class="font-mono">{toZone.name}</code>
													{:else}
														Click to <strong>allow</strong> traffic from
														<code class="font-mono">{fromZone.name}</code> →
														<code class="font-mono">{toZone.name}</code>
													{/if}
												</Tooltip.Content>
											</Tooltip.Portal>
										</Tooltip.Root>
									</Tooltip.Provider>
								{/if}
							</td>
						{/each}
					</tr>
				{/each}
			</tbody>
		</table>
	</div>

	<!-- Legend -->
	<Separator />
	<div class="flex flex-wrap items-center gap-4 text-xs text-muted-foreground">
		<span class="font-medium text-foreground">Legend:</span>
		<span class="flex items-center gap-1.5">
			<span
				class="inline-flex items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-500/20 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:text-emerald-400"
			>
				<CheckIcon data-icon="inline-start" />
				Allowed
			</span>
			<span>— traffic forwarded between zones</span>
		</span>
		<span class="flex items-center gap-1.5">
			<span
				class="inline-flex items-center gap-1 rounded-full border border-border bg-muted px-2 py-0.5 text-xs font-medium text-muted-foreground"
			>
				<XIcon data-icon="inline-start" />
				Blocked
			</span>
			<span>— traffic dropped between zones</span>
		</span>
		<span class="flex items-center gap-1.5">
			<span class="rounded border border-border bg-muted/50 px-2 py-0.5 font-mono">—</span>
			<span>— intra-zone loop (same zone)</span>
		</span>
	</div>
</div>
