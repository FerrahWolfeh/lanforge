<script lang="ts">
	import * as Popover from "$lib/components/ui/popover";
	import { Button } from "$lib/components/ui/button";
	import { Badge } from "$lib/components/ui/badge";
	import BookmarkIcon from "@lucide/svelte/icons/bookmark";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import CheckIcon from "@lucide/svelte/icons/check";
	import type { DnsAdblockUrlEntry } from "$lib/api/types";

	let {
		sources = [],
		onAdd = () => {},
	}: {
		sources?: DnsAdblockUrlEntry[];
		onAdd?: (url: string, title: string) => void;
	} = $props();

	const PRESETS = [
		{
			title: "StevenBlack Unified",
			description: "Adware and malware blocking hosts list (~150k rules).",
			url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
			badge: "Standard",
		},
		{
			title: "OISD Basic",
			description: "Ad, tracking, and telemetry blocklist (~250k rules).",
			url: "https://big.oisd.nl/domainswg",
			badge: "General",
		},
		{
			title: "Hägezi Multi Normal",
			description: "Tracker, phishing, and telemetry domain list.",
			url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/multi.txt",
			badge: "Strict",
		},
		{
			title: "AdGuard Mobile & Tracking",
			description: "Mobile app trackers and telemetry domain list.",
			url: "https://v.firebog.net/hosts/AdguardDNS.txt",
			badge: "Mobile",
		},
		{
			title: "Windows SpyBlocker",
			description: "Telemetry, diagnostics, and update tracking endpoints in Windows.",
			url: "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
			badge: "Telemetry",
		},
	];
</script>

<Popover.Root>
	<Popover.Trigger
		class="inline-flex items-center justify-center gap-1.5 h-8 px-2.5 rounded-md border border-input bg-background hover:bg-accent hover:text-accent-foreground text-xs font-medium transition-colors cursor-pointer"
	>
		<BookmarkIcon class="size-3.5 text-muted-foreground" />
		<span>Presets</span>
	</Popover.Trigger>
	<Popover.Content
		class="w-80 sm:w-96 p-3 shadow-xl border border-border/70 bg-popover text-popover-foreground z-50 rounded-lg flex flex-col gap-2.5 max-h-[80vh] overflow-y-auto"
		side="bottom"
		align="end"
	>
		<div class="flex items-center justify-between border-b border-border/50 pb-2">
			<div class="flex items-center gap-1.5 font-semibold text-xs text-foreground">
				<BookmarkIcon class="size-3.5 text-primary" />
				<span>Community Blocklist Presets</span>
			</div>
			<Badge variant="outline" class="text-[9px] font-mono">Curated</Badge>
		</div>

		<div class="flex flex-col gap-2">
			{#each PRESETS as p (p.url)}
				{@const installed = sources.some((s) => s.url === p.url)}
				<div class="flex flex-col p-2.5 rounded-md border border-border/60 bg-muted/20 gap-1.5">
					<div class="flex items-center justify-between gap-2">
						<span class="font-semibold text-xs text-foreground truncate">{p.title}</span>
						<Badge variant="secondary" class="text-[9px] px-1.5 py-0 font-mono">
							{p.badge}
						</Badge>
					</div>
					<p class="text-[11px] text-muted-foreground line-clamp-2">
						{p.description}
					</p>
					<div class="flex items-center justify-between pt-1 border-t border-border/30">
						<span class="text-[10px] font-mono text-muted-foreground truncate max-w-[170px]" title={p.url}>
							{p.url.replace(/^https?:\/\//, "")}
						</span>

						{#if installed}
							<Badge variant="outline" class="text-[9px] bg-emerald-500/10 text-emerald-600 border-emerald-500/20 gap-1 h-5 px-1.5">
								<CheckIcon class="size-2.5" />
								Active
							</Badge>
						{:else}
							<Button
								variant="outline"
								size="sm"
								class="h-6 text-[10px] px-2 gap-1"
								onclick={() => onAdd(p.url, p.title)}
							>
								<PlusIcon class="size-2.5" />
								Add
							</Button>
						{/if}
					</div>
				</div>
			{/each}
		</div>
	</Popover.Content>
</Popover.Root>
