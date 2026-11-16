<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Select from "$lib/components/ui/select";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import InfoPopover from "$lib/components/InfoPopover.svelte";
	import { auth } from "$lib/stores/auth.svelte";
	import { logLevel, setLogLevel } from "$lib/api/client";
	import type { LogLevelStatus, LogSource } from "$lib/api/types";
	import { toast } from "svelte-sonner";
	import { onMount } from "svelte";
	import ScrollTextIcon from "@lucide/svelte/icons/scroll-text";
	import Loader2Icon from "@lucide/svelte/icons/loader-2";
	import RotateCcwIcon from "@lucide/svelte/icons/rotate-ccw";

	const PRESETS = [
		{ value: "error", label: "Error" },
		{ value: "warn", label: "Warning" },
		{ value: "info", label: "Info" },
		{ value: "debug", label: "Debug (Lanforge)" },
		{ value: "debug-all", label: "Debug (everything)" },
		{ value: "trace", label: "Trace (Lanforge)" },
		{ value: "trace-all", label: "Trace (everything)" },
	];
	const DURATIONS: { value: string; label: string; secs: number | null }[] = [
		{ value: "saved", label: "Until changed", secs: null },
		{ value: "900", label: "15 minutes", secs: 900 },
		{ value: "1800", label: "30 minutes", secs: 1800 },
		{ value: "3600", label: "1 hour", secs: 3600 },
		{ value: "7200", label: "2 hours", secs: 7200 },
		{ value: "28800", label: "8 hours", secs: 28800 },
		{ value: "86400", label: "24 hours", secs: 86400 },
	];
	/** Mirrors `LogFilter::MAX_TRACE_SECS`. */
	const TRACE_MAX_SECS = 3600;
	const SOURCE_LABEL: Record<LogSource, string> = {
		default: "Default",
		env: "RUST_LOG",
		saved: "Saved",
		temporary: "Temporary",
	};

	// Debug needs `diagnostics` (operators too); trace is admin-only on the server.
	const canChange = $derived(auth.can("diagnostics"));
	const isAdmin = $derived(auth.can("admin"));

	let current = $state<LogLevelStatus | null>(null);
	let loading = $state(true);
	let saving = $state(false);
	let filter = $state("info");
	let duration = $state("saved");
	let secondsLeft = $state<number | null>(null);

	/** Whether any item of a filter is at trace (`trace`, `trace-all`, `module=trace`). */
	function hasTrace(text: string): boolean {
		return text.split(",").some((item) => {
			const level = item.includes("=") ? item.split("=")[1] : item.replace(/-all\s*$/i, "");
			return level.trim().toLowerCase() === "trace";
		});
	}

	const trace = $derived(hasTrace(filter));
	const preset = $derived(PRESETS.find((p) => p.value === filter.trim().toLowerCase()));
	const durationSecs = $derived(DURATIONS.find((d) => d.value === duration)?.secs ?? null);
	const invalid = $derived(
		!filter.trim()
			? "Enter a filter"
			: trace && !isAdmin
				? "Only an admin can turn on trace logging"
				: trace && (durationSecs === null || durationSecs > TRACE_MAX_SECS)
					? "Trace lasts at most 1 hour"
					: null,
	);

	function show(status: LogLevelStatus) {
		current = status;
		secondsLeft = status.expires_in_secs;
		filter = status.active;
		duration = status.source === "temporary" ? duration : "saved";
	}

	async function load() {
		try {
			show(await logLevel());
		} catch (err) {
			toast.error(`Could not read the log filter: ${err instanceof Error ? err.message : String(err)}`);
		} finally {
			loading = false;
		}
	}

	function choosePreset(value: string | undefined) {
		if (!value) return;
		filter = value;
		// Trace is never kept on: offer the shortest limit instead of an invalid "until changed".
		if (hasTrace(value) && (durationSecs === null || durationSecs > TRACE_MAX_SECS)) {
			duration = "1800";
		}
	}

	async function apply() {
		saving = true;
		try {
			show(await setLogLevel({ filter: filter.trim(), duration_secs: durationSecs }));
			toast.success(
				durationSecs === null
					? `Log filter saved: ${current?.active}`
					: `Log filter set to ${current?.active} for ${DURATIONS.find((d) => d.secs === durationSecs)?.label}`,
			);
		} catch (err) {
			toast.error(`Could not change the log filter: ${err instanceof Error ? err.message : String(err)}`);
		} finally {
			saving = false;
		}
	}

	async function reset() {
		saving = true;
		try {
			show(await setLogLevel({ filter: null, duration_secs: null }));
			toast.success(`Log filter back to ${current?.active}`);
		} catch (err) {
			toast.error(`Could not reset the log filter: ${err instanceof Error ? err.message : String(err)}`);
		} finally {
			saving = false;
		}
	}

	function formatLeft(secs: number): string {
		const h = Math.floor(secs / 3600);
		const m = Math.floor((secs % 3600) / 60);
		const s = secs % 60;
		if (h > 0) return `${h}h ${m}m`;
		if (m > 0) return `${m}m ${s}s`;
		return `${s}s`;
	}

	let reloadTimer: ReturnType<typeof setTimeout> | undefined;
	const counting = $derived(secondsLeft !== null);

	onMount(() => {
		load();
		return () => clearTimeout(reloadTimer);
	});

	// Counts a temporary filter down, and reads the daemon again once it has ended. The interval
	// only runs while a temporary filter is active.
	$effect(() => {
		if (!counting) return;
		const timer = setInterval(() => {
			if (secondsLeft === null) return;
			secondsLeft = Math.max(0, secondsLeft - 1);
			if (secondsLeft === 0) {
				secondsLeft = null;
				reloadTimer = setTimeout(load, 1500);
			}
		}, 1000);
		return () => clearInterval(timer);
	});
</script>

<Card.Root>
	<Card.Header class="pb-2">
		<Card.Title class="flex items-center gap-2 text-sm font-medium">
			<ScrollTextIcon class="text-muted-foreground size-4" />
			Logging
			<InfoPopover
				title="Daemon log filter"
				description="What lanforged writes to the journal. Debug covers Lanforge's own modules; 'everything' adds libraries (HTTP, TLS, database). A filter kept until changed survives restarts; a timed one returns to the saved filter (or RUST_LOG) when it ends."
			/>
		</Card.Title>
	</Card.Header>
	<Card.Content class="flex flex-col gap-3">
		{#if loading}
			<Skeleton class="h-4 w-full" />
			<Skeleton class="h-4 w-1/2" />
		{:else if current}
			<dl class="text-sm">
				<div class="flex items-center justify-between py-0.5">
					<dt class="text-muted-foreground">Active</dt>
					<dd class="flex items-center gap-2">
						<span class="font-mono text-xs font-medium">{current.active}</span>
						<Badge variant={current.source === "temporary" ? "secondary" : "outline"} class="text-xs">
							{SOURCE_LABEL[current.source]}
						</Badge>
					</dd>
				</div>
				{#if current.source === "temporary"}
					<div class="flex justify-between py-0.5">
						<dt class="text-muted-foreground">Ends in</dt>
						<dd class="font-mono text-xs">{secondsLeft === null ? "…" : formatLeft(secondsLeft)}</dd>
					</div>
					<div class="flex justify-between py-0.5">
						<dt class="text-muted-foreground">Then</dt>
						<dd class="font-mono text-xs">{current.saved ?? current.boot}</dd>
					</div>
				{:else if current.source === "saved"}
					<div class="flex justify-between py-0.5">
						<dt class="text-muted-foreground">Without it</dt>
						<dd class="font-mono text-xs">{current.boot}</dd>
					</div>
				{/if}
			</dl>

			{#if canChange}
				<div class="flex flex-col gap-2 border-t pt-3">
					<div class="grid grid-cols-2 gap-2">
						<Select.Root type="single" value={preset?.value ?? ""} onValueChange={choosePreset}>
							<Select.Trigger class="h-8 text-xs" aria-label="Log level">
								{preset?.label ?? "Custom"}
							</Select.Trigger>
							<Select.Content>
								{#each PRESETS as p (p.value)}
									<Select.Item
										value={p.value}
										class="text-xs"
										disabled={hasTrace(p.value) && !isAdmin}
									>
										{p.label}
									</Select.Item>
								{/each}
							</Select.Content>
						</Select.Root>
						<Select.Root type="single" value={duration} onValueChange={(v) => (duration = v ?? "saved")}>
							<Select.Trigger class="h-8 text-xs" aria-label="How long">
								{DURATIONS.find((d) => d.value === duration)?.label}
							</Select.Trigger>
							<Select.Content>
								{#each DURATIONS as d (d.value)}
									<Select.Item
										value={d.value}
										class="text-xs"
										disabled={trace && (d.secs === null || d.secs > TRACE_MAX_SECS)}
									>
										{d.label}
									</Select.Item>
								{/each}
							</Select.Content>
						</Select.Root>
					</div>
					<Input
						bind:value={filter}
						class="h-8 font-mono text-xs"
						aria-label="Log filter"
						placeholder="info,lanforge_dns=debug"
						spellcheck={false}
					/>
					{#if invalid}
						<p class="text-destructive text-xs">{invalid}</p>
					{/if}
					<div class="flex justify-end gap-2">
						{#if current.source === "saved" || current.source === "temporary"}
							<Button variant="ghost" size="sm" class="h-7 text-xs" onclick={reset} disabled={saving}>
								<RotateCcwIcon data-icon="inline-start" />
								Reset
							</Button>
						{/if}
						<Button size="sm" class="h-7 text-xs" onclick={apply} disabled={saving || !!invalid}>
							{#if saving}
								<Loader2Icon data-icon="inline-start" class="animate-spin" />
							{/if}
							Apply
						</Button>
					</div>
				</div>
			{/if}
		{/if}
	</Card.Content>
</Card.Root>
