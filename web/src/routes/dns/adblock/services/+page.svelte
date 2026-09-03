<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Switch } from "$lib/components/ui/switch";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import ShieldAlertIcon from "@lucide/svelte/icons/shield-alert";
	import LockIcon from "@lucide/svelte/icons/lock";
	import SearchIcon from "@lucide/svelte/icons/search";
	import EyeIcon from "@lucide/svelte/icons/eye";
	import CheckIcon from "@lucide/svelte/icons/check";
	import { toast } from "svelte-sonner";

	interface BlockedService {
		id: string;
		name: string;
		category: string;
		domainCount: number;
		blocked: boolean;
		description: string;
	}

	let safeSearchGoogle = $state(false);
	let safeSearchBing = $state(false);
	let safeSearchYoutube = $state(false);
	let safeSearchDuckDuckGo = $state(false);

	let services = $state<BlockedService[]>([
		// Social
		{
			id: "tiktok",
			name: "TikTok",
			category: "Social Media",
			domainCount: 16,
			blocked: false,
			description: "Blocks TikTok videos, API, and content distribution networks.",
		},
		{
			id: "facebook",
			name: "Facebook & Instagram",
			category: "Social Media",
			domainCount: 24,
			blocked: false,
			description: "Meta social platforms, tracking pixels, and CDNs.",
		},
		{
			id: "twitter",
			name: "X (Twitter)",
			category: "Social Media",
			domainCount: 12,
			blocked: false,
			description: "X.com, t.co link wrappers, and analytics endpoints.",
		},
		{
			id: "reddit",
			name: "Reddit",
			category: "Social Media",
			domainCount: 8,
			blocked: false,
			description: "Reddit website, official app API, and media hosters.",
		},
		// Gaming
		{
			id: "discord",
			name: "Discord",
			category: "Gaming & Chat",
			domainCount: 14,
			blocked: false,
			description: "Discord voice servers, gateways, and media CDNs.",
		},
		{
			id: "steam",
			name: "Steam",
			category: "Gaming & Chat",
			domainCount: 20,
			blocked: false,
			description: "Steam store, community, and game download servers.",
		},
		{
			id: "roblox",
			name: "Roblox",
			category: "Gaming & Chat",
			domainCount: 11,
			blocked: false,
			description: "Roblox game client endpoints and asset servers.",
		},
		{
			id: "twitch",
			name: "Twitch",
			category: "Gaming & Chat",
			domainCount: 13,
			blocked: false,
			description: "Twitch live stream ingest, chat IRC, and API endpoints.",
		},
		// Streaming
		{
			id: "netflix",
			name: "Netflix",
			category: "Streaming",
			domainCount: 18,
			blocked: false,
			description: "Netflix video streaming endpoints and device authentication.",
		},
		{
			id: "spotify",
			name: "Spotify",
			category: "Streaming",
			domainCount: 15,
			blocked: false,
			description: "Music playback streams, podcast delivery, and client API.",
		},
		// Protective Categories
		{
			id: "adult",
			name: "Adult Content (18+)",
			category: "Protection",
			domainCount: 42000,
			blocked: false,
			description: "Known pornography, explicit domains, and adult material.",
		},
		{
			id: "gambling",
			name: "Gambling & Betting",
			category: "Protection",
			domainCount: 18500,
			blocked: false,
			description: "Online casinos, sports betting, and slot machine portals.",
		},
		{
			id: "crypto",
			name: "Cryptocurrency Miners",
			category: "Protection",
			domainCount: 6200,
			blocked: true,
			description: "In-browser CoinHive scripts, miner pools, and drainer domains.",
		},
	]);

	const blockedCount = $derived(services.filter((s) => s.blocked).length);

	function toggleService(id: string, newVal: boolean) {
		services = services.map((s) =>
			s.id === id ? { ...s, blocked: newVal } : s,
		);
		const service = services.find((s) => s.id === id);
		if (service) {
			toast.info(
				newVal
					? `Enforced blocking for ${service.name}`
					: `Removed blocking for ${service.name}`,
			);
		}
	}

	function toggleSafeSearch(engine: string, newVal: boolean) {
		toast.success(
			newVal
				? `Enforced SafeSearch for ${engine}`
				: `Disabled SafeSearch for ${engine}`,
		);
	}
</script>

<div class="space-y-6">
	<!-- SafeSearch Enforcement Card -->
	<Card.Root>
		<Card.Header class="pb-3 border-b border-border/50">
			<div class="flex items-center justify-between">
				<div class="flex items-center gap-2">
					<SearchIcon class="size-4 text-sky-500" />
					<Card.Title class="text-base font-semibold">
						Enforce SafeSearch Across LAN
					</Card.Title>
				</div>
				<Badge variant="outline" class="font-mono text-xs">DNS CNAME Rewriting</Badge>
			</div>
			<Card.Description class="text-xs">
				Forces strict SafeSearch filtering on search engines by transparently intercepting domain requests and pointing them to official safe search endpoints.
			</Card.Description>
		</Card.Header>

		<Card.Content class="p-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
			<!-- Google -->
			<div class="flex items-center justify-between p-3 rounded-lg border bg-card">
				<div class="flex flex-col gap-0.5">
					<span class="text-xs font-semibold text-foreground">Google</span>
					<span class="text-[11px] text-muted-foreground">forcesafesearch.google.com</span>
				</div>
				<Switch
					bind:checked={safeSearchGoogle}
					onCheckedChange={(val) => toggleSafeSearch("Google", val)}
				/>
			</div>

			<!-- Bing -->
			<div class="flex items-center justify-between p-3 rounded-lg border bg-card">
				<div class="flex flex-col gap-0.5">
					<span class="text-xs font-semibold text-foreground">Bing</span>
					<span class="text-[11px] text-muted-foreground">strict.bing.com</span>
				</div>
				<Switch
					bind:checked={safeSearchBing}
					onCheckedChange={(val) => toggleSafeSearch("Bing", val)}
				/>
			</div>

			<!-- YouTube -->
			<div class="flex items-center justify-between p-3 rounded-lg border bg-card">
				<div class="flex flex-col gap-0.5">
					<span class="text-xs font-semibold text-foreground">YouTube Restricted</span>
					<span class="text-[11px] text-muted-foreground">restrict.youtube.com</span>
				</div>
				<Switch
					bind:checked={safeSearchYoutube}
					onCheckedChange={(val) => toggleSafeSearch("YouTube", val)}
				/>
			</div>

			<!-- DuckDuckGo -->
			<div class="flex items-center justify-between p-3 rounded-lg border bg-card">
				<div class="flex flex-col gap-0.5">
					<span class="text-xs font-semibold text-foreground">DuckDuckGo</span>
					<span class="text-[11px] text-muted-foreground">safe.duckduckgo.com</span>
				</div>
				<Switch
					bind:checked={safeSearchDuckDuckGo}
					onCheckedChange={(val) => toggleSafeSearch("DuckDuckGo", val)}
				/>
			</div>
		</Card.Content>
	</Card.Root>

	<!-- Blocked Services Grid -->
	<Card.Root>
		<Card.Header class="pb-3 border-b border-border/50">
			<div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
				<div>
					<div class="flex items-center gap-2">
						<LockIcon class="size-4 text-primary" />
						<Card.Title class="text-base font-semibold">
							Service Blocking ({blockedCount} Active)
						</Card.Title>
					</div>
					<Card.Description class="text-xs">
						Block specific apps and platforms with 1-click domain sets without affecting the rest of the web.
					</Card.Description>
				</div>

				<div class="flex items-center gap-2">
					<Button
						variant="outline"
						size="sm"
						class="text-xs h-8"
						onclick={() => {
							services = services.map((s) => ({ ...s, blocked: false }));
							toast.info("Unblocked all services");
						}}
					>
						Unblock All
					</Button>
				</div>
			</div>
		</Card.Header>

		<Card.Content class="p-4 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
			{#each services as svc (svc.id)}
				<div
					class={[
						"flex flex-col justify-between p-3.5 rounded-lg border transition-all",
						svc.blocked
							? "border-rose-500/30 bg-rose-500/5 dark:bg-rose-950/10"
							: "bg-card border-border/60",
					].join(" ")}
				>
					<div class="flex items-start justify-between gap-2">
						<div class="flex flex-col gap-0.5">
							<div class="flex items-center gap-2">
								<span class="font-semibold text-xs text-foreground">
									{svc.name}
								</span>
								<Badge variant="secondary" class="text-[10px] px-1.5 py-0 font-mono">
									{svc.category}
								</Badge>
							</div>
							<p class="text-[11px] text-muted-foreground mt-1">
								{svc.description}
							</p>
						</div>

						<Switch
							checked={svc.blocked}
							onCheckedChange={(val) => toggleService(svc.id, val)}
						/>
					</div>

					<div class="flex items-center justify-between pt-2.5 mt-2 border-t border-border/40 text-[11px]">
						<span class="font-mono text-muted-foreground">
							{svc.domainCount.toLocaleString()} domains
						</span>

						{#if svc.blocked}
							<span class="text-rose-500 font-semibold flex items-center gap-1 font-mono text-[10px]">
								<ShieldAlertIcon class="size-3" />
								Blocked
							</span>
						{:else}
							<span class="text-muted-foreground flex items-center gap-1 font-mono text-[10px]">
								Permitted
							</span>
						{/if}
					</div>
				</div>
			{/each}
		</Card.Content>
	</Card.Root>
</div>
