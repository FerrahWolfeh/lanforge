<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Tabs from "$lib/components/ui/tabs";
	import * as Table from "$lib/components/ui/table";
	import * as AlertDialog from "$lib/components/ui/alert-dialog";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Label } from "$lib/components/ui/label";
	import { Switch } from "$lib/components/ui/switch";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { Separator } from "$lib/components/ui/separator";
	import {
		status,
		dbStats,
		dbVacuum,
		dbPrune,
		dbLogClean,
		dbReset,
		exportSystemConfig,
		exportSystemConfigToml,
		importSystemConfig,
		switchDbEngine,
	} from "$lib/api/client";
	import type {
		StatusResponse,
		DbMetrics,
		SystemConfigExport,
		SystemConfigImportResponse,
		DbEngineSwitchRequest,
	} from "$lib/api/types";
	import { toast } from "svelte-sonner";
	import { onMount, onDestroy } from "svelte";
	import { fly } from "svelte/transition";
	import { cubicOut } from "svelte/easing";

	import DatabaseIcon from "@lucide/svelte/icons/database";
	import HardDriveIcon from "@lucide/svelte/icons/hard-drive";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import CheckCircleIcon from "@lucide/svelte/icons/check-circle";
	import CheckIcon from "@lucide/svelte/icons/check";
	import AlertTriangleIcon from "@lucide/svelte/icons/triangle-alert";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import SparklesIcon from "@lucide/svelte/icons/sparkles";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import FileTextIcon from "@lucide/svelte/icons/file-text";
	import DownloadIcon from "@lucide/svelte/icons/download";
	import UploadIcon from "@lucide/svelte/icons/upload";
	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import ServerIcon from "@lucide/svelte/icons/server";
	import ClockIcon from "@lucide/svelte/icons/clock";
	import InfoIcon from "@lucide/svelte/icons/info";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import XCircleIcon from "@lucide/svelte/icons/x-circle";
	import LayersIcon from "@lucide/svelte/icons/layers";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import FileDownIcon from "@lucide/svelte/icons/file-down";
	import FileUpIcon from "@lucide/svelte/icons/file-up";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import LockIcon from "@lucide/svelte/icons/lock";
	import EyeIcon from "@lucide/svelte/icons/eye";
	import EyeOffIcon from "@lucide/svelte/icons/eye-off";
	import RotateCcwIcon from "@lucide/svelte/icons/rotate-ccw";
	import ExternalLinkIcon from "@lucide/svelte/icons/external-link";

	// Page data
	let systemStatus = $state<StatusResponse | null>(null);
	let metrics = $state<DbMetrics | null>(null);
	let configExport = $state<SystemConfigExport | null>(null);
	let loading = $state(true);
	let refreshing = $state(false);
	let activeTab = $state("inventory");
	let refreshInterval: ReturnType<typeof setInterval> | null = null;

	// Operation states
	let vacuuming = $state(false);
	let pruning = $state(false);
	let logCleaning = $state(false);
	let wiping = $state(false);
	let exporting = $state(false);
	let exportingToml = $state(false);
	let importing = $state(false);

	// Maintenance last run tracking
	let lastVacuumTime = $state<number | null>(null);
	let lastPruneTime = $state<number | null>(null);
	let lastLogCleanTime = $state<number | null>(null);

	// Danger zone wipe dialog
	let wipeDialogOpen = $state(false);
	let wipeConfirmText = $state("");

	// Import state
	let importFileInput: HTMLInputElement | null = null;
	let selectedFile = $state<File | null>(null);
	let importOverwrite = $state(false);
	let importResult = $state<SystemConfigImportResponse | null>(null);
	let showImportResultDialog = $state(false);

	// Storage configuration form state
	let formStorageType = $state<"persistent" | "volatile">("persistent");
	let formUrl = $state("/var/lib/lanforge/lanforge.redb");
	let formFlushInterval = $state(60);
	let formLogUrl = $state("/tmp/lanforge-logs.jsonl");

	// Derived helpers
	const isInMemory = $derived.by(() => {
		const path = systemStatus?.db?.path?.toLowerCase() || "";
		return (
			!path ||
			path === "memory" ||
			path === "none" ||
			path === "mock" ||
			path.startsWith("/tmp") ||
			path.startsWith("/run") ||
			path.includes(":memory:")
		);
	});

	const engineLabel = $derived(
		isInMemory ? "Volatile / RAM (tmpfs)" : "Persistent (redb)",
	);

	// Correctly check health using boolean comparison
	const isHealthy = $derived.by(() => {
		if (!metrics) return true;
		if (typeof metrics.last_error === "boolean") {
			return !metrics.last_error;
		}
		return metrics.last_error === 0;
	});

	let baselineForm = $state<string | null>(null);

	function serializeForm(): string {
		return JSON.stringify({
			storageType: formStorageType,
			url: formUrl.trim(),
			flush: Number(formFlushInterval),
			logUrl: formLogUrl.trim(),
		});
	}

	function syncFormFromStatus() {
		const rawPath = systemStatus?.db?.path || "";
		if (isInMemory || rawPath.startsWith("/tmp") || rawPath.startsWith("/run")) {
			formStorageType = "volatile";
			formUrl = rawPath || "/run/lanforge/config.redb";
		} else {
			formStorageType = "persistent";
			formUrl = rawPath || "/var/lib/lanforge/config.redb";
		}
		formFlushInterval = 60;
		formLogUrl = "/run/lanforge/runtime.redb";

		baselineForm = serializeForm();
	}

	// Dirty tracking
	const isDirty = $derived.by(() => {
		if (!baselineForm) return false;
		return serializeForm() !== baselineForm;
	});

	// Reactive live generated TOML
	const computedToml = $derived.by(() => {
		let urlVal = formUrl.trim();
		if (!urlVal) {
			urlVal =
				formStorageType === "persistent"
					? "/var/lib/lanforge/config.redb"
					: "/run/lanforge/config.redb";
		}
		return `[database]
config_path = "${urlVal}"
runtime_path = "${formLogUrl || "/run/lanforge/runtime.redb"}"
flush_interval = ${formFlushInterval || 60}`;
	});

	// Inventory of stored entities
	interface InventorySubsystem {
		id: string;
		title: string;
		category: string;
		icon: any;
		count: number;
		unit: string;
		route: string;
		description: string;
	}

	const inventoryItems = $derived.by<InventorySubsystem[]>(() => {
		const cfg = configExport;
		const devCount = metrics?.devices_written ?? 0;
		const staticHostCount = cfg?.hosts?.length ?? 0;
		const dhcpv4Pools = cfg?.dhcp_v4_pools?.length ?? 0;
		const dhcpv6Pools = cfg?.dhcp_v6_pools?.length ?? 0;
		const dnsRewrites = cfg?.dns_rewrites?.length ?? 0;
		const dnsUpstreams = cfg?.dns_upstreams?.length ?? 0;
		const dnsReverseResolvers = cfg?.dns_reverse_resolvers?.length ?? 0;
		const adblockSources = cfg?.dns_adblock_urls?.length ?? 0;
		const allowlistRules = cfg?.dns_allowlist?.length ?? 0;
		const apiTokens = cfg?.api_tokens?.length ?? 0;

		return [
			{
				id: "devices",
				title: "Discovered Devices",
				category: "Network Inventory",
				icon: ServerIcon,
				count: devCount,
				unit: "devices",
				route: "/network/devices",
				description:
					"Discovered dynamic and active host records with IP, MAC, and lease associations",
			},
			{
				id: "hosts",
				title: "Static Hosts & Reservations",
				category: "Network Inventory",
				icon: HardDriveIcon,
				count: staticHostCount,
				unit: "static bindings",
				route: "/network/hosts",
				description:
					"Persistent hostnames and fixed IP address bindings",
			},
			{
				id: "dhcp_pools",
				title: "DHCP Scopes & Pools",
				category: "DHCP Orchestration",
				icon: NetworkIcon,
				count: dhcpv4Pools + dhcpv6Pools,
				unit: "pools",
				route: "/dhcp/pools",
				description: `Managed allocation pools (${dhcpv4Pools} IPv4 pools, ${dhcpv6Pools} IPv6 pools)`,
			},
			{
				id: "dns_rewrites",
				title: "Custom DNS Rewrites",
				category: "DNS Engine",
				icon: GlobeIcon,
				count: dnsRewrites,
				unit: "records",
				route: "/dns/rewrites",
				description:
					"Authoritative A, AAAA, CNAME, and TXT internal domain overrides",
			},
			{
				id: "dns_upstreams",
				title: "DNS Forwarders & Resolvers",
				category: "DNS Engine",
				icon: GlobeIcon,
				count: dnsUpstreams + dnsReverseResolvers,
				unit: "resolvers",
				route: "/dns/resolver",
				description: `Upstream targets (${dnsUpstreams} general upstreams, ${dnsReverseResolvers} reverse zones)`,
			},
			{
				id: "adblock",
				title: "Adblock Sources & Rules",
				category: "Content Filtering",
				icon: ShieldCheckIcon,
				count: adblockSources + allowlistRules,
				unit: "sources & rules",
				route: "/dns/adblock",
				description: `Filter feeds (${adblockSources} blocklists, ${allowlistRules} allowlist exceptions)`,
			},
			{
				id: "api_tokens",
				title: "API Access Tokens",
				category: "Security & Auth",
				icon: LockIcon,
				count: apiTokens,
				unit: "active tokens",
				route: "/system/auth",
				description:
					"Programmatic bearer tokens for CLI and external integration access",
			},
		];
	});

	const totalStoredEntities = $derived(
		inventoryItems.reduce((acc, item) => acc + item.count, 0),
	);

	async function loadAll(silent = false) {
		if (!silent) refreshing = true;
		try {
			const [s, m, cfg] = await Promise.all([
				status().catch(() => null),
				dbStats().catch(() => null),
				exportSystemConfig().catch(() => null),
			]);
			if (s) {
				const isFirstLoad = !baselineForm;
				systemStatus = s;
				if (isFirstLoad || !isDirty) {
					syncFormFromStatus();
				}
			}
			if (m) metrics = m;
			if (cfg) configExport = cfg;
		} catch {
			if (!silent) toast.error("Failed to fetch database information");
		} finally {
			if (!silent) {
				loading = false;
				refreshing = false;
			}
		}
	}

	onMount(() => {
		loadAll();
		refreshInterval = setInterval(() => {
			loadAll(true);
		}, 10000);
	});

	onDestroy(() => {
		if (refreshInterval) clearInterval(refreshInterval);
	});

	function formatBytes(bytes: number): string {
		if (!bytes || bytes === 0) return "0 B";
		const k = 1024;
		const sizes = ["B", "KB", "MB", "GB", "TB"];
		const i = Math.floor(Math.log(bytes) / Math.log(k));
		return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
	}

	function formatTimeAgo(secs: number | null | undefined): string {
		if (secs === null || secs === undefined) return "Never";
		if (secs < 60) return `${secs}s ago`;
		if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
		return `${Math.floor(secs / 3600)}h ago`;
	}

	function formatTimestamp(ts: number | null | undefined): string {
		if (!ts || ts === 0) return "Never";
		const d = new Date(ts * 1000);
		return d.toLocaleTimeString([], {
			hour: "2-digit",
			minute: "2-digit",
			second: "2-digit",
		});
	}

	async function handleVacuum() {
		vacuuming = true;
		try {
			await dbVacuum();
			lastVacuumTime = Math.floor(Date.now() / 1000);
			toast.success("Database vacuum completed", {
				description:
					"Table spaces and index pages optimized successfully.",
			});
			await loadAll(true);
		} catch (e: any) {
			toast.error("Vacuum failed", {
				description: e?.message || "Internal server error",
			});
		} finally {
			vacuuming = false;
		}
	}

	async function handlePrune() {
		pruning = true;
		try {
			await dbPrune();
			lastPruneTime = Math.floor(Date.now() / 1000);
			toast.success("Zombie devices pruned", {
				description:
					"Purged inactive dynamic devices with no hostname nor active lease.",
			});
			await loadAll(true);
		} catch (e: any) {
			toast.error("Prune failed", {
				description: e?.message || "Internal server error",
			});
		} finally {
			pruning = false;
		}
	}

	async function handleLogClean() {
		logCleaning = true;
		try {
			await dbLogClean();
			lastLogCleanTime = Math.floor(Date.now() / 1000);
			toast.success("Transient logs cleaned", {
				description:
					"Log buffers and temporary query history truncated.",
			});
			await loadAll(true);
		} catch (e: any) {
			toast.error("Log clean failed", {
				description: e?.message || "Internal server error",
			});
		} finally {
			logCleaning = false;
		}
	}

	async function handleReset() {
		if (wipeConfirmText !== "wipe") {
			toast.error("Confirmation text mismatch. Type 'wipe' to confirm.");
			return;
		}

		wiping = true;
		try {
			await dbReset();
			toast.success("Database reset complete", {
				description:
					"All persistent state and transient caches were purged.",
			});
			wipeDialogOpen = false;
			wipeConfirmText = "";
			await loadAll(true);
		} catch (e: any) {
			toast.error("Reset failed", {
				description: e?.message || "Internal server error",
			});
		} finally {
			wiping = false;
		}
	}

	async function handleExport() {
		exporting = true;
		try {
			const config = await exportSystemConfig();
			const jsonStr = JSON.stringify(config, null, 2);
			const blob = new Blob([jsonStr], { type: "application/json" });
			const url = URL.createObjectURL(blob);
			const a = document.createElement("a");
			const dateStr = new Date().toISOString().slice(0, 10);
			a.href = url;
			a.download = `lanforge-config-${dateStr}.json`;
			document.body.appendChild(a);
			a.click();
			document.body.removeChild(a);
			URL.revokeObjectURL(url);
			toast.success("Configuration exported successfully", {
				description: "Saved aggregated JSON persistence snapshot.",
			});
		} catch (e: any) {
			toast.error("Export failed", {
				description: e?.message || "Internal server error",
			});
		} finally {
			exporting = false;
		}
	}

	async function handleExportToml() {
		exportingToml = true;
		try {
			const tomlStr = await exportSystemConfigToml();
			const blob = new Blob([tomlStr], { type: "text/plain;charset=utf-8" });
			const url = URL.createObjectURL(blob);
			const a = document.createElement("a");
			const dateStr = new Date().toISOString().slice(0, 10);
			a.href = url;
			a.download = `lanforge-${dateStr}.toml`;
			document.body.appendChild(a);
			a.click();
			document.body.removeChild(a);
			URL.revokeObjectURL(url);
			toast.success("TOML configuration exported", {
				description: "Saved consolidated lanforge.toml file.",
			});
		} catch (e: any) {
			toast.error("Export failed", {
				description: e?.message || "Internal server error",
			});
		} finally {
			exportingToml = false;
		}
	}

	function handleFileSelected(event: Event) {
		const target = event.target as HTMLInputElement;
		if (target.files && target.files.length > 0) {
			selectedFile = target.files[0];
		}
	}

	async function handleImport() {
		if (!selectedFile) {
			toast.error("Please select a JSON configuration file to import.");
			return;
		}

		importing = true;
		try {
			const text = await selectedFile.text();
			let parsed: SystemConfigExport;
			try {
				parsed = JSON.parse(text);
			} catch {
				toast.error("Invalid JSON file", {
					description:
						"The selected file is not a valid JSON document.",
				});
				importing = false;
				return;
			}

			parsed.overwrite = importOverwrite;

			const resp = await importSystemConfig(parsed);
			importResult = resp;
			showImportResultDialog = true;

			if (resp.total_success) {
				toast.success("Configuration imported successfully");
			} else {
				toast.warning(
					"Configuration import finished with some warnings",
				);
			}

			selectedFile = null;
			if (importFileInput) importFileInput.value = "";
			await loadAll(true);
		} catch (e: any) {
			toast.error("Import failed", {
				description: e?.message || "Internal server error",
			});
		} finally {
			importing = false;
		}
	}

	function copyTomlSample() {
		navigator.clipboard.writeText(computedToml);
		toast.success("Configuration copied to clipboard", {
			description: "Paste into your /etc/lanforge/lanforge.toml file.",
		});
	}

	function handleDiscardForm() {
		syncFormFromStatus();
		toast.info("Settings reverted to active daemon parameters");
	}

	let applyingEngineSwitch = $state(false);

	async function handleApplyEngineSwitch() {
		applyingEngineSwitch = true;
		try {
			const targetUrl =
				formUrl.trim() ||
				(formStorageType === "persistent"
					? "/var/lib/lanforge/lanforge.redb"
					: "/run/lanforge/lanforge.redb");

			const payload: DbEngineSwitchRequest = {
				engine: "redb",
				url: targetUrl,
			};

			await switchDbEngine(payload);

			toast.success("Storage configuration updated. Soft-rebooting daemon...", {
				description:
					"The daemon is soft-rebooting internal services with the new storage configuration.",
				duration: 6000,
			});

			baselineForm = serializeForm();

			setTimeout(() => {
				loadAll(true);
			}, 2500);
		} catch (e: any) {
			toast.error("Failed to update storage configuration", {
				description: e?.message || "Internal server error",
			});
		} finally {
			applyingEngineSwitch = false;
		}
	}
</script>

<div class="flex flex-col gap-6 w-full">
	<!-- Page Header -->
	<div
		class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
	>
		<div class="flex items-center gap-3">
			<div
				class="flex size-11 items-center justify-center rounded-2xl bg-primary/10 text-primary shrink-0"
			>
				<DatabaseIcon class="size-6" />
			</div>
			<div class="flex flex-col gap-1">
				<div class="flex flex-wrap items-center gap-2.5">
					<h1 class="text-2xl font-bold tracking-tight">
						Database & Persistence
					</h1>
					{#if loading && !systemStatus}
						<Skeleton class="h-5 w-28 rounded-full" />
					{:else if isInMemory}
						<Badge
							variant="outline"
							class="border-amber-500/25 bg-amber-500/10 text-amber-600 dark:text-amber-400 font-medium text-xs gap-1.5"
						>
							<AlertTriangleIcon class="size-3" />
							Volatile / RAM (tmpfs)
						</Badge>
					{:else}
						<Badge
							variant="outline"
							class="border-emerald-500/25 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 font-medium text-xs"
						>
							<span class="relative flex size-2 mr-1.5">
								<span
									class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"
								></span>
								<span
									class="relative inline-flex rounded-full size-2 bg-emerald-500"
								></span>
							</span>
							redb (Connected)
						</Badge>
					{/if}
				</div>
				<p class="text-sm text-muted-foreground">
					Storage engine health, persistent inventory, background
					flushes, and configuration management.
				</p>
			</div>
		</div>

		<div class="flex items-center gap-2 shrink-0">
			<Button
				variant="outline"
				size="sm"
				onclick={() => loadAll()}
				disabled={loading || refreshing}
				class="transition-transform duration-150 active:scale-95 transform-gpu"
			>
				<RefreshCwIcon
					class={refreshing ? "animate-spin" : ""}
					data-icon="inline-start"
				/>
				Refresh
			</Button>

			<Button
				variant="outline"
				size="sm"
				onclick={handleExportToml}
				disabled={exportingToml}
				class="transition-transform duration-150 active:scale-95 transform-gpu shadow-sm gap-1.5"
			>
				<FileTextIcon
					class={exportingToml ? "animate-spin size-4" : "size-4"}
				/>
				Export TOML
			</Button>

			<Button
				variant="default"
				size="sm"
				onclick={handleExport}
				disabled={exporting}
				class="transition-transform duration-150 active:scale-95 transform-gpu shadow-sm gap-1.5"
			>
				<FileDownIcon
					class={exporting ? "animate-spin size-4" : "size-4"}
				/>
				Download Snapshot
			</Button>
		</div>
	</div>

	<!-- Top 4 High-Density Metric Cards -->
	<div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
		<!-- Card 1: Storage Engine -->
		<Card.Root>
			<Card.Header class="pb-2">
				<Card.Title
					class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider text-muted-foreground"
				>
					<span>Storage Engine</span>
					<HardDriveIcon class="size-4 text-indigo-400" />
				</Card.Title>
			</Card.Header>
			<Card.Content class="flex flex-col gap-1.5 pt-1">
				{#if loading && !systemStatus}
					<Skeleton class="h-7 w-32" />
					<Skeleton class="mt-2 h-4 w-40" />
				{:else}
					<div
						class="text-xl font-bold tracking-tight text-foreground flex items-center gap-2"
					>
						<span>{engineLabel}</span>
					</div>
					<div
						class="flex flex-col gap-0.5 border-t pt-1.5 text-xs text-muted-foreground"
					>
						<div class="flex justify-between items-center">
							<span class="text-[11px]">Backend Mode:</span>
							<Badge
								variant="outline"
								class="text-[10px] px-1.5 py-0 h-4 font-mono font-normal"
							>
								{isInMemory ? "RAM / tmpfs" : "redb (Disk)"}
							</Badge>
						</div>
						<p
							class="text-[11px] text-muted-foreground font-mono truncate mt-0.5"
							title={systemStatus?.db?.path || "redb"}
						>
							{systemStatus?.db?.path || "redb (embedded)"}
						</p>
					</div>
				{/if}
			</Card.Content>
		</Card.Root>

		<!-- Card 2: Persistence Flushes -->
		<Card.Root>
			<Card.Header class="pb-2">
				<Card.Title
					class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider text-muted-foreground"
				>
					<span>Persistence Cadence</span>
					<ActivityIcon class="size-4 text-emerald-400" />
				</Card.Title>
			</Card.Header>
			<Card.Content class="flex flex-col gap-1.5 pt-1">
				{#if loading && !metrics}
					<Skeleton class="h-7 w-20" />
					<Skeleton class="mt-2 h-4 w-32" />
				{:else}
					<div
						class="text-xl font-bold tracking-tight text-foreground flex items-baseline gap-2"
					>
						<span
							>{(
								metrics?.flush_count ?? 0
							).toLocaleString()}</span
						>
						<span class="text-xs font-normal text-muted-foreground"
							>total flushes</span
						>
					</div>
					<div
						class="flex flex-col gap-0.5 border-t pt-1.5 text-xs text-muted-foreground"
					>
						<div class="flex justify-between items-center">
							<span class="text-[11px]">Last Sync:</span>
							<span
								class="text-foreground text-[11px] font-medium font-mono"
							>
								{formatTimeAgo(
									systemStatus?.db?.last_flush_secs_ago,
								)}
							</span>
						</div>
						<div
							class="flex justify-between items-center text-[11px]"
						>
							<span>Interval:</span>
							<span class="text-foreground font-medium"
								>60s tick</span
							>
						</div>
					</div>
				{/if}
			</Card.Content>
		</Card.Root>

		<!-- Card 3: Stored Records & Inventory -->
		<Card.Root>
			<Card.Header class="pb-2">
				<Card.Title
					class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider text-muted-foreground"
				>
					<span>Stored Records</span>
					<ServerIcon class="size-4 text-blue-400" />
				</Card.Title>
			</Card.Header>
			<Card.Content class="flex flex-col gap-1.5 pt-1">
				{#if loading && !metrics}
					<Skeleton class="h-7 w-24" />
					<Skeleton class="mt-2 h-4 w-36" />
				{:else}
					<div
						class="text-xl font-bold tracking-tight text-foreground flex items-baseline gap-2"
					>
						<span>{totalStoredEntities.toLocaleString()}</span>
						<span class="text-xs font-normal text-muted-foreground"
							>entities</span
						>
					</div>
					<div
						class="flex flex-col gap-0.5 border-t pt-1.5 text-xs text-muted-foreground"
					>
						<div class="flex justify-between items-center">
							<span class="text-[11px]">Devices written:</span>
							<span
								class="text-foreground text-[11px] font-medium font-mono"
							>
								{(
									metrics?.devices_written ?? 0
								).toLocaleString()}
							</span>
						</div>
						<div
							class="flex justify-between items-center text-[11px]"
						>
							<span>Disk footprint:</span>
							<span class="text-foreground font-medium font-mono">
								{formatBytes(systemStatus?.db?.size_bytes ?? 0)}
							</span>
						</div>
					</div>
				{/if}
			</Card.Content>
		</Card.Root>

		<!-- Card 4: Engine Health -->
		<Card.Root>
			<Card.Header class="pb-2">
				<Card.Title
					class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider text-muted-foreground"
				>
					<span>Engine Health</span>
					{#if isHealthy}
						<CheckCircleIcon class="size-4 text-emerald-400" />
					{:else}
						<AlertTriangleIcon class="size-4 text-amber-400" />
					{/if}
				</Card.Title>
			</Card.Header>
			<Card.Content class="flex flex-col gap-1.5 pt-1">
				{#if loading && !metrics}
					<Skeleton class="h-7 w-24" />
					<Skeleton class="mt-2 h-4 w-36" />
				{:else if isHealthy}
					<div
						class="text-xl font-bold text-emerald-500 flex items-center gap-2"
					>
						<span>Optimal</span>
					</div>
					<div
						class="flex flex-col gap-0.5 border-t pt-1.5 text-xs text-muted-foreground"
					>
						<div
							class="flex justify-between items-center text-[11px]"
						>
							<span>Write errors:</span>
							<Badge
								variant="outline"
								class="text-[10px] px-1.5 py-0 h-4 border-emerald-500/30 text-emerald-500 font-mono"
							>
								0 errors
							</Badge>
						</div>
						<span
							class="text-[11px] text-muted-foreground truncate mt-0.5"
						>
							Clean persistent write lock
						</span>
					</div>
				{:else}
					<div
						class="text-xl font-bold text-amber-500 flex items-center gap-2"
					>
						<span>Attention</span>
					</div>
					<div
						class="flex flex-col gap-0.5 border-t pt-1.5 text-xs text-muted-foreground"
					>
						<div
							class="flex justify-between items-center text-[11px]"
						>
							<span>Last status:</span>
							<span class="text-amber-500 font-medium"
								>Write error detected</span
							>
						</div>
						<span
							class="text-[11px] text-muted-foreground truncate mt-0.5"
						>
							Check daemon storage logs
						</span>
					</div>
				{/if}
			</Card.Content>
		</Card.Root>
	</div>

	<!-- Volatile Mode Banner -->
	{#if !loading && isInMemory}
		<Card.Root class="border-amber-500/30 bg-amber-500/5">
			<Card.Content class="pt-6">
				<div class="flex items-start gap-4">
					<div
						class="p-2 rounded-xl bg-amber-500/10 text-amber-600 dark:text-amber-400 shrink-0"
					>
						<AlertTriangleIcon class="size-5" />
					</div>
					<div class="flex flex-col gap-1">
						<h3 class="text-sm font-semibold text-foreground">
							Running with Volatile / RAM Storage
						</h3>
						<p
							class="text-xs text-muted-foreground leading-relaxed"
						>
							The daemon is currently storing data in volatile memory (tmpfs/RAM). Dynamic lease assignments,
							static host mappings, and DNS rules will reset if the system reboots. This is ideal for OpenWrt
							or embedded routers to protect flash storage. To persist across reboots, configure a persistent
							database path (e.g. <code class="font-mono text-foreground">/var/lib/lanforge/lanforge.redb</code>) in the <button
								type="button"
								class="font-medium text-foreground underline hover:text-primary transition-colors cursor-pointer"
								onclick={() => (activeTab = "settings")}
								>Storage Settings tab</button
							>
							or export a backup in
							<button
								type="button"
								class="font-medium text-foreground underline hover:text-primary transition-colors cursor-pointer"
								onclick={() => (activeTab = "backup")}
								>Backup &amp; Restore</button
							>.
						</p>
					</div>
				</div>
			</Card.Content>
		</Card.Root>
	{/if}

	<!-- Tabs Navigation -->
	<Tabs.Root bind:value={activeTab} class="space-y-6">
		<div class="flex items-center justify-between">
			<Tabs.List
				class="grid grid-cols-2 md:grid-cols-4 w-full md:w-auto md:inline-grid"
			>
				<Tabs.Trigger value="inventory" class="gap-2">
					<LayersIcon class="size-4" />
					<span>Live Inventory</span>
				</Tabs.Trigger>
				<Tabs.Trigger value="settings" class="gap-2">
					<SlidersIcon class="size-4" />
					<span>Storage Settings</span>
					{#if isDirty}
						<span
							class="size-2 rounded-full bg-amber-500 animate-pulse ml-0.5"
						></span>
					{/if}
				</Tabs.Trigger>
				<Tabs.Trigger value="maintenance" class="gap-2">
					<SparklesIcon class="size-4" />
					<span>Maintenance</span>
				</Tabs.Trigger>
				<Tabs.Trigger value="backup" class="gap-2">
					<DownloadIcon class="size-4" />
					<span>Backup & Restore</span>
				</Tabs.Trigger>
			</Tabs.List>
		</div>

		<!-- TAB 1: LIVE INVENTORY -->
		<Tabs.Content
			value="inventory"
			class="space-y-6 focus-visible:outline-none"
		>
			<div
				in:fly={{ y: 12, duration: 240, easing: cubicOut }}
				class="flex flex-col gap-6"
			>
				<!-- Subsystems Table Card -->
				<Card.Root>
					<Card.Header class="pb-3">
						<div
							class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2"
						>
							<div class="space-y-1">
								<Card.Title
									class="text-base flex items-center gap-2 font-semibold"
								>
									<LayersIcon class="size-4 text-primary" />
									Persistent Subsystem Inventory
								</Card.Title>
								<Card.Description class="text-xs">
									Aggregated state records actively maintained
									in daemon memory and synchronized to the
									storage backend.
								</Card.Description>
							</div>
							<Badge
								variant="outline"
								class="font-mono text-xs w-fit"
							>
								{totalStoredEntities} total entities
							</Badge>
						</div>
					</Card.Header>
					<Card.Content>
						<div class="rounded-md border overflow-x-auto">
							<Table.Root>
								<Table.Header>
									<Table.Row>
										<Table.Head class="w-[260px]"
											>Subsystem / Domain</Table.Head
										>
										<Table.Head>Category</Table.Head>
										<Table.Head class="text-right"
											>Record Count</Table.Head
										>
										<Table.Head
											>Backend Persistence</Table.Head
										>
										<Table.Head class="text-right"
											>Action</Table.Head
										>
									</Table.Row>
								</Table.Header>
								<Table.Body>
									{#each inventoryItems as item}
										<Table.Row
											class="hover:bg-muted/50 transition-colors"
										>
											<Table.Cell class="font-medium">
												<div
													class="flex items-center gap-2.5"
												>
													<div
														class="flex size-7 items-center justify-center rounded-lg bg-muted text-muted-foreground shrink-0"
													>
														<item.icon
															class="size-4"
														/>
													</div>
													<div class="flex flex-col">
														<span
															class="text-xs font-semibold text-foreground"
															>{item.title}</span
														>
														<span
															class="text-[11px] text-muted-foreground line-clamp-1"
															>{item.description}</span
														>
													</div>
												</div>
											</Table.Cell>
											<Table.Cell>
												<Badge
													variant="secondary"
													class="text-[11px] font-normal"
												>
													{item.category}
												</Badge>
											</Table.Cell>
											<Table.Cell
												class="text-right font-mono font-semibold text-xs"
											>
												{item.count.toLocaleString()}
												<span
													class="text-[10px] font-normal text-muted-foreground ml-1"
													>{item.unit}</span
												>
											</Table.Cell>
											<Table.Cell>
												{#if isInMemory}
													<Badge
														variant="outline"
														class="border-amber-500/25 bg-amber-500/10 text-amber-600 dark:text-amber-400 text-[10px]"
													>
														RAM Only
													</Badge>
												{:else}
													<Badge
														variant="outline"
														class="border-emerald-500/25 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 text-[10px]"
													>
														<CheckIcon
															class="size-3 mr-1"
														/>
														Persistent (redb)
													</Badge>
												{/if}
											</Table.Cell>
											<Table.Cell class="text-right">
												<Button
													variant="ghost"
													size="sm"
													class="h-7 text-xs gap-1 text-muted-foreground hover:text-foreground"
													href={item.route}
												>
													<span>View</span>
													<ExternalLinkIcon
														class="size-3"
													/>
												</Button>
											</Table.Cell>
										</Table.Row>
									{/each}
								</Table.Body>
							</Table.Root>
						</div>
					</Card.Content>
				</Card.Root>
			</div>
		</Tabs.Content>

		<!-- TAB 2: STORAGE SETTINGS -->
		<Tabs.Content
			value="settings"
			class="space-y-6 focus-visible:outline-none"
		>
			<div
				in:fly={{ y: 12, duration: 240, easing: cubicOut }}
				class="flex flex-col gap-6"
			>
				<!-- Storage Engine Form -->
				<Card.Root>
					<Card.Header>
						<div
							class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2"
						>
							<div class="space-y-1">
								<Card.Title
									class="text-base flex items-center gap-2 font-semibold"
								>
									<SlidersIcon class="size-5 text-primary" />
									Storage Engine Configuration
								</Card.Title>
								<Card.Description class="text-xs">
									Configure how the Lanforge persistence layer
									connects to its storage backend.
								</Card.Description>
							</div>
							{#if isDirty}
								<Badge
									variant="outline"
									class="border-amber-500/30 bg-amber-500/10 text-amber-500 text-xs gap-1"
								>
									<span
										class="size-1.5 rounded-full bg-amber-500 animate-pulse"
									></span>
									Unsaved Changes
								</Badge>
							{/if}
						</div>
					</Card.Header>
					<Card.Content class="space-y-6">
						<!-- Storage Mode Selector -->
						<div class="space-y-2">
							<Label class="text-xs font-semibold"
								>Storage Persistence Mode</Label
							>
							<div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
								<button
									type="button"
									class="flex flex-col gap-1 p-3.5 rounded-xl border text-left transition-all {formStorageType ===
									'persistent'
										? 'border-primary bg-primary/5 ring-1 ring-primary'
										: 'border-border hover:bg-muted/40'}"
									onclick={() => {
										formStorageType = "persistent";
										if (formUrl.startsWith("/run") || formUrl.startsWith("/tmp") || formUrl === "memory") {
											formUrl = "/var/lib/lanforge/lanforge.redb";
										}
									}}
								>
									<div
										class="flex items-center justify-between w-full"
									>
										<span
											class="text-sm font-bold text-foreground"
											>Persistent Storage (Disk / Flash)</span
										>
										{#if formStorageType === "persistent"}
											<CheckIcon
												class="size-4 text-primary"
											/>
										{/if}
									</div>
									<p class="text-xs text-muted-foreground">
										Default for standard Linux servers, homelabs, and VMs. Preserves all configuration and state across reboots.
									</p>
								</button>

								<button
									type="button"
									class="flex flex-col gap-1 p-3.5 rounded-xl border text-left transition-all {formStorageType ===
									'volatile'
										? 'border-amber-500 bg-amber-500/5 ring-1 ring-amber-500'
										: 'border-border hover:bg-muted/40'}"
									onclick={() => {
										formStorageType = "volatile";
										if (formUrl.startsWith("/var/lib")) {
											formUrl = "/run/lanforge/lanforge.redb";
										}
									}}
								>
									<div
										class="flex items-center justify-between w-full"
									>
										<span
											class="text-sm font-bold text-foreground"
											>Volatile Storage / RAM (tmpfs)</span
										>
										{#if formStorageType === "volatile"}
											<CheckIcon
												class="size-4 text-amber-500"
											/>
										{/if}
									</div>
									<p class="text-xs text-muted-foreground">
										Recommended for OpenWrt routers and SBCs with fragile SPI flash memory. Stores the redb file in RAM (/run or /tmp).
									</p>
								</button>
							</div>
						</div>

						<Separator />

						<!-- Database Paths and Cadence -->
						<div class="space-y-4">
							<div class="space-y-1.5">
								<Label for="cfg-path" class="text-xs font-semibold"
									>Database File Path</Label
								>
								<Input
									id="cfg-path"
									bind:value={formUrl}
									placeholder={formStorageType === "persistent"
										? "/var/lib/lanforge/config.redb"
										: "/run/lanforge/config.redb"}
									class="text-xs font-mono"
								/>
								<p class="text-[11px] text-muted-foreground">
									Path to the persistent configuration <code class="text-foreground">redb</code> database file.
								</p>
							</div>

							<div class="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-1">
								<div class="space-y-1.5">
									<Label for="cfg-flush" class="text-xs font-semibold"
										>Flush Interval (seconds)</Label
									>
									<Input
										id="cfg-flush"
										type="number"
										min="5"
										max="600"
										bind:value={formFlushInterval}
										class="text-xs font-mono"
									/>
									<p class="text-[10px] text-muted-foreground">
										Cadence of background state sync to storage.
									</p>
								</div>
								<div class="space-y-1.5">
									<Label for="cfg-logpath" class="text-xs font-semibold"
										>Runtime Database Path</Label
									>
									<Input
										id="cfg-logpath"
										bind:value={formLogUrl}
										placeholder="/run/lanforge/runtime.redb"
										class="text-xs font-mono"
									/>
									<p class="text-[10px] text-muted-foreground">
										Path for volatile runtime database (active leases, audit logs, query history in tmpfs).
									</p>
								</div>
							</div>
						</div>

						<Separator />

						<!-- Live Generated TOML Preview & Instructions -->
						<div class="space-y-3">
							<div class="flex items-center justify-between">
								<div class="space-y-0.5">
									<h4
										class="text-sm font-semibold text-foreground"
									>
										Generated Configuration (lanforge.toml)
									</h4>
									<p class="text-xs text-muted-foreground">
										Add or replace this section in your <span
											class="font-mono text-foreground font-medium"
											>/etc/lanforge/lanforge.toml</span
										> configuration file.
									</p>
								</div>
								<Button
									variant="outline"
									size="sm"
									class="gap-1.5 text-xs"
									onclick={copyTomlSample}
								>
									<CopyIcon class="size-3.5" />
									Copy TOML
								</Button>
							</div>

							<pre
								class="rounded-lg bg-muted/60 border p-4 font-mono text-xs text-foreground overflow-x-auto select-all leading-relaxed"><code
									>{computedToml}</code
								></pre>
						</div>

						<!-- Action bar when dirty -->
						{#if isDirty}
							<div
								class="flex flex-col sm:flex-row items-center justify-between gap-3 rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-xs"
							>
								<div
									class="flex items-center gap-2 text-amber-600 dark:text-amber-400 font-medium"
								>
									<AlertTriangleIcon
										class="size-4 shrink-0"
									/>
									<span
										>Unsaved changes in form. Copy
										configuration to your daemon file to
										activate.</span
									>
								</div>
								<div class="flex items-center gap-2">
									<Button
										variant="ghost"
										size="sm"
										class="h-8 gap-1 text-xs"
										onclick={handleDiscardForm}
									>
										<RotateCcwIcon class="size-3.5" />
										Revert
									</Button>
									<Button
										variant="default"
										size="sm"
										class="h-8 gap-1.5 text-xs shadow-sm"
										onclick={handleApplyEngineSwitch}
										disabled={applyingEngineSwitch}
									>
										{#if applyingEngineSwitch}
											<RefreshCwIcon
												class="size-3.5 animate-spin"
											/>
											Migrating &amp; Rebooting...
										{:else}
											<CheckCircleIcon class="size-3.5" />
											Save &amp; Switch Engine
										{/if}
									</Button>
								</div>
							</div>
						{/if}
					</Card.Content>
				</Card.Root>
			</div>
		</Tabs.Content>

		<!-- TAB 3: MAINTENANCE & OPERATIONS -->
		<Tabs.Content
			value="maintenance"
			class="space-y-6 focus-visible:outline-none"
		>
			<div
				in:fly={{ y: 12, duration: 240, easing: cubicOut }}
				class="flex flex-col gap-6"
			>
				<div class="grid grid-cols-1 gap-4 md:grid-cols-3">
					<!-- Vacuum -->
					<Card.Root class="flex flex-col justify-between">
						<Card.Header>
							<Card.Title
								class="flex items-center gap-2 text-base font-semibold"
							>
								<SparklesIcon class="size-4 text-primary" />
								Storage Optimization
							</Card.Title>
							<Card.Description
								class="text-xs leading-relaxed mt-1"
							>
								Runs backend storage VACUUM on relational tables
								to defragment pages, reclaim disk space, and
								optimize B-tree indices.
							</Card.Description>
						</Card.Header>
						<Card.Content class="pt-0 space-y-3">
							{#if lastVacuumTime}
								<p
									class="text-[11px] text-emerald-500 flex items-center gap-1 font-medium"
								>
									<CheckIcon class="size-3" />
									Executed {formatTimeAgo(
										Math.floor(Date.now() / 1000) -
											lastVacuumTime,
									)}
								</p>
							{/if}
							<Button
								variant="outline"
								size="sm"
								class="w-full gap-2 text-xs"
								onclick={handleVacuum}
								disabled={vacuuming}
							>
								<SparklesIcon
									class={vacuuming
										? "animate-spin size-4"
										: "size-4"}
								/>
								{vacuuming ? "Optimizing..." : "Run VACUUM"}
							</Button>
						</Card.Content>
					</Card.Root>

					<!-- Prune -->
					<Card.Root class="flex flex-col justify-between">
						<Card.Header>
							<Card.Title
								class="flex items-center gap-2 text-base font-semibold"
							>
								<Trash2Icon class="size-4 text-primary" />
								Prune Zombie Devices
							</Card.Title>
							<Card.Description
								class="text-xs leading-relaxed mt-1"
							>
								Scans and purges dynamic devices that do not
								have hostnames, active leases, nor recent
								network activity.
							</Card.Description>
						</Card.Header>
						<Card.Content class="pt-0 space-y-3">
							{#if lastPruneTime}
								<p
									class="text-[11px] text-emerald-500 flex items-center gap-1 font-medium"
								>
									<CheckIcon class="size-3" />
									Executed {formatTimeAgo(
										Math.floor(Date.now() / 1000) -
											lastPruneTime,
									)}
								</p>
							{/if}
							<Button
								variant="outline"
								size="sm"
								class="w-full gap-2 text-xs"
								onclick={handlePrune}
								disabled={pruning}
							>
								<Trash2Icon
									class={pruning
										? "animate-spin size-4"
										: "size-4"}
								/>
								{pruning ? "Pruning..." : "Prune Inactive"}
							</Button>
						</Card.Content>
					</Card.Root>

					<!-- Log Clean -->
					<Card.Root class="flex flex-col justify-between">
						<Card.Header>
							<Card.Title
								class="flex items-center gap-2 text-base font-semibold"
							>
								<FileTextIcon class="size-4 text-primary" />
								Clean Transient Logs
							</Card.Title>
							<Card.Description
								class="text-xs leading-relaxed mt-1"
							>
								Truncates buffered DNS query logs and system
								lifecycle event records stored in temporary log
								files.
							</Card.Description>
						</Card.Header>
						<Card.Content class="pt-0 space-y-3">
							{#if lastLogCleanTime}
								<p
									class="text-[11px] text-emerald-500 flex items-center gap-1 font-medium"
								>
									<CheckIcon class="size-3" />
									Executed {formatTimeAgo(
										Math.floor(Date.now() / 1000) -
											lastLogCleanTime,
									)}
								</p>
							{/if}
							<Button
								variant="outline"
								size="sm"
								class="w-full gap-2 text-xs"
								onclick={handleLogClean}
								disabled={logCleaning}
							>
								<FileTextIcon
									class={logCleaning
										? "animate-spin size-4"
										: "size-4"}
								/>
								{logCleaning
									? "Cleaning..."
									: "Clean Log Buffer"}
							</Button>
						</Card.Content>
					</Card.Root>
				</div>

				<!-- Danger Zone -->
				<Card.Root class="border-destructive/30 bg-destructive/5">
					<Card.Header>
						<Card.Title
							class="flex items-center gap-2 text-destructive text-base font-semibold"
						>
							<AlertTriangleIcon class="size-5" />
							Danger Zone: Storage Reset
						</Card.Title>
						<Card.Description
							class="text-xs text-muted-foreground leading-relaxed mt-1"
						>
							Permanently clear all persistent data cascades
							(hosts, leases, custom rewrites, DHCP pools, and
							token tables). This action is irreversible.
						</Card.Description>
					</Card.Header>
					<Card.Content
						class="flex items-center justify-between pt-0"
					>
						<div class="text-xs text-muted-foreground">
							Requires explicit manual confirmation with
							confirmation word.
						</div>
						<Button
							variant="destructive"
							size="sm"
							onclick={() => (wipeDialogOpen = true)}
						>
							Reset Database
						</Button>
					</Card.Content>
				</Card.Root>
			</div>
		</Tabs.Content>

		<!-- TAB 4: CONFIGURATION BACKUP -->
		<Tabs.Content
			value="backup"
			class="space-y-6 focus-visible:outline-none"
		>
			<div
				in:fly={{ y: 12, duration: 240, easing: cubicOut }}
				class="grid grid-cols-1 gap-6 lg:grid-cols-2"
			>
				<!-- Export Configuration Card -->
				<Card.Root>
					<Card.Header>
						<Card.Title
							class="flex items-center gap-2 text-base font-semibold"
						>
							<FileDownIcon class="size-5 text-primary" />
							Export System Configuration
						</Card.Title>
						<Card.Description class="text-xs leading-relaxed mt-1">
							Generate and download consolidated configuration as a directly deployable
							lanforge.toml file or an aggregated JSON persistence snapshot.
						</Card.Description>
					</Card.Header>
					<Card.Content class="space-y-4">
						<div
							class="rounded-lg border bg-muted/30 p-3 space-y-2 text-xs"
						>
							<div class="font-medium text-foreground">
								Included Subsystems:
							</div>
							<ul
								class="grid grid-cols-1 sm:grid-cols-2 gap-1.5 text-muted-foreground"
							>
								<li class="flex items-center gap-1.5">
									<CheckIcon
										class="size-3.5 text-emerald-500"
									/>
									Static Hosts & Leases
								</li>
								<li class="flex items-center gap-1.5">
									<CheckIcon
										class="size-3.5 text-emerald-500"
									/>
									DHCPv4 & DHCPv6 Pools
								</li>
								<li class="flex items-center gap-1.5">
									<CheckIcon
										class="size-3.5 text-emerald-500"
									/>
									DHCP Options & TFTP
								</li>
								<li class="flex items-center gap-1.5">
									<CheckIcon
										class="size-3.5 text-emerald-500"
									/>
									DNS Rewrites & Upstreams
								</li>
								<li class="flex items-center gap-1.5">
									<CheckIcon
										class="size-3.5 text-emerald-500"
									/>
									Adblock Rules & Sources
								</li>
								<li class="flex items-center gap-1.5">
									<CheckIcon
										class="size-3.5 text-emerald-500"
									/>
									Reverse DNS Resolvers
								</li>
								<li class="flex items-center gap-1.5">
									<CheckIcon
										class="size-3.5 text-emerald-500"
									/>
									IPv6 RA Prefixes & Options
								</li>
								<li class="flex items-center gap-1.5">
									<CheckIcon
										class="size-3.5 text-emerald-500"
									/>
									PPPoE WAN Concentrator
								</li>
							</ul>
						</div>

						<div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
							<Button
								variant="default"
								class="gap-2"
								onclick={handleExportToml}
								disabled={exportingToml}
							>
								<FileTextIcon
									class={exportingToml
										? "animate-spin size-4"
										: "size-4"}
								/>
								{exportingToml
									? "Generating TOML..."
									: "Download lanforge.toml"}
							</Button>

							<Button
								variant="outline"
								class="gap-2"
								onclick={handleExport}
								disabled={exporting}
							>
								<DownloadIcon
									class={exporting
										? "animate-spin size-4"
										: "size-4"}
								/>
								{exporting
									? "Generating Snapshot..."
									: "Download JSON Snapshot"}
							</Button>
						</div>
					</Card.Content>
				</Card.Root>

				<!-- Import Configuration Card -->
				<Card.Root>
					<Card.Header>
						<Card.Title
							class="flex items-center gap-2 text-base font-semibold"
						>
							<FileUpIcon class="size-5 text-primary" />
							Restore System Configuration
						</Card.Title>
						<Card.Description class="text-xs leading-relaxed mt-1">
							Apply an exported JSON configuration file to
							populate or restore daemon persistence tables.
						</Card.Description>
					</Card.Header>
					<Card.Content class="space-y-4">
						<div class="space-y-2">
							<Label
								for="config-file-upload"
								class="text-xs font-medium"
								>Select JSON File</Label
							>
							<input
								id="config-file-upload"
								type="file"
								accept=".json,application/json"
								bind:this={importFileInput}
								onchange={handleFileSelected}
								class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-xs shadow-sm file:border-0 file:bg-transparent file:text-xs file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring cursor-pointer"
							/>
							{#if selectedFile}
								<p class="text-xs text-muted-foreground">
									Selected: <span
										class="font-medium text-foreground"
										>{selectedFile.name}</span
									>
									({formatBytes(selectedFile.size)})
								</p>
							{/if}
						</div>

						<div
							class="flex items-center justify-between rounded-lg border p-3"
						>
							<div class="space-y-0.5">
								<Label
									class="text-xs font-medium cursor-pointer"
									for="overwrite-switch"
								>
									Overwrite Existing Records
								</Label>
								<p class="text-[11px] text-muted-foreground">
									Purges current records before importing
									instead of merging entities.
								</p>
							</div>
							<Switch
								id="overwrite-switch"
								bind:checked={importOverwrite}
							/>
						</div>

						<Button
							variant="default"
							class="w-full gap-2"
							onclick={handleImport}
							disabled={importing || !selectedFile}
						>
							<UploadIcon
								class={importing
									? "animate-spin size-4"
									: "size-4"}
							/>
							{importing
								? "Restoring Configuration..."
								: "Apply Configuration"}
						</Button>
					</Card.Content>
				</Card.Root>
			</div>
		</Tabs.Content>
	</Tabs.Root>
</div>

<!-- Wipe Confirmation Dialog -->
<AlertDialog.Root bind:open={wipeDialogOpen}>
	<AlertDialog.Content>
		<AlertDialog.Header>
			<AlertDialog.Title class="flex items-center gap-2 text-destructive">
				<AlertTriangleIcon class="size-5" />
				Confirm Complete Database Wipe
			</AlertDialog.Title>
			<AlertDialog.Description class="space-y-2 text-xs">
				<p>
					This action will cascade-delete all stored static devices,
					active DHCP lease reservations, DNS custom rewrites,
					upstreams, adblock lists, and API access tokens.
				</p>
				<p class="font-semibold text-foreground">
					To proceed, type <span
						class="font-mono text-destructive underline">wipe</span
					> into the box below:
				</p>
			</AlertDialog.Description>
		</AlertDialog.Header>
		<div class="py-2">
			<Input
				bind:value={wipeConfirmText}
				placeholder="Type 'wipe' to confirm"
				class="font-mono text-sm"
			/>
		</div>
		<AlertDialog.Footer>
			<AlertDialog.Cancel onclick={() => (wipeConfirmText = "")}>
				Cancel
			</AlertDialog.Cancel>
			<AlertDialog.Action
				class="bg-destructive text-destructive-foreground hover:bg-destructive/90"
				onclick={handleReset}
				disabled={wipeConfirmText !== "wipe" || wiping}
			>
				{wiping ? "Wiping Database..." : "Permanently Wipe"}
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>

<!-- Import Results Dialog -->
<AlertDialog.Root bind:open={showImportResultDialog}>
	<AlertDialog.Content class="max-w-lg">
		<AlertDialog.Header>
			<AlertDialog.Title class="flex items-center gap-2">
				{#if importResult?.total_success}
					<CheckCircleIcon class="size-5 text-emerald-500" />
					Configuration Restored
				{:else}
					<AlertTriangleIcon class="size-5 text-amber-500" />
					Restore Completed with Warnings
				{/if}
			</AlertDialog.Title>
			<AlertDialog.Description class="text-xs">
				Detailed report of the imported subsystem configuration entries:
			</AlertDialog.Description>
		</AlertDialog.Header>

		{#if importResult}
			<div class="max-h-64 overflow-y-auto space-y-2 py-2">
				{#each importResult.results as res}
					<div
						class="flex items-center justify-between rounded-md border p-2 text-xs"
					>
						<span class="font-mono font-medium">{res.section}</span>
						{#if res.success}
							<Badge
								variant="outline"
								class="border-emerald-500/25 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
							>
								<CheckIcon class="size-3 mr-1" />
								{res.count} imported
							</Badge>
						{:else}
							<Badge
								variant="outline"
								class="border-destructive/25 bg-destructive/10 text-destructive truncate max-w-[200px]"
								title={res.error || "failed"}
							>
								<XCircleIcon class="size-3 mr-1" />
								{res.error || "failed"}
							</Badge>
						{/if}
					</div>
				{/each}
			</div>
		{/if}

		<AlertDialog.Footer>
			<AlertDialog.Action
				onclick={() => (showImportResultDialog = false)}
			>
				Close
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
