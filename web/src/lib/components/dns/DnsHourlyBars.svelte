<script lang="ts">
	import type { DeviceDnsBucket } from "$lib/api/types";

	/** Hourly bars over the last day: queries in the brand gradient, blocked ones drawn over them from the bottom. */
	let { rate, ariaLabel }: { rate: DeviceDnsBucket[]; ariaLabel?: string } = $props();

	const uid = $props.id();
	const W = 600;
	const H = 110;
	const PAD = 4;

	const BAR_RADIUS = 1.5;
	const hourFormat = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", hourCycle: "h23" });

	/** One bar per hourly bucket, bottom-aligned. */
	const chart = $derived.by(() => {
		if (!rate.length) return null;
		const max = Math.max(1, ...rate.map((b) => b.total));
		const slot = W / rate.length;
		const barW = slot * 0.75;
		const inset = (slot - barW) / 2;
		const scale = (v: number) => (v / max) * (H - PAD);
		const bars = rate.map((b, i) => {
			const x = i * slot + inset;
			const h = scale(b.total);
			const top = H - h;
			const r = Math.min(BAR_RADIUS, h, barW / 2);
			// Rounded top corners only: the bar sits on the baseline.
			const path =
				h > 0
					? `M${x.toFixed(1)},${H} V${(top + r).toFixed(1)} Q${x.toFixed(1)},${top.toFixed(1)} ${(x + r).toFixed(1)},${top.toFixed(1)} H${(x + barW - r).toFixed(1)} Q${(x + barW).toFixed(1)},${top.toFixed(1)} ${(x + barW).toFixed(1)},${(top + r).toFixed(1)} V${H} Z`
					: "";
			const time = hourFormat.format(new Date(b.timestamp * 1000));
			return {
				key: b.timestamp,
				x,
				w: barW,
				path,
				blockedY: H - scale(b.blocked),
				blockedH: scale(b.blocked),
				blocked: b.blocked,
				label: `${time} · ${b.total} ${b.total === 1 ? "query" : "queries"}, ${b.blocked} blocked`,
			};
		});
		return { bars, max };
	});
	const gradientId = $derived(`dns-bar-${uid}`);
</script>

{#if chart}
	<div class="px-3 pt-3">
		<svg
			viewBox="0 0 {W} {H}"
			class="block h-auto w-full"
			role="img"
			aria-label={ariaLabel ?? `Queries per hour over the last 24 hours, busiest hour ${chart.max}`}
			preserveAspectRatio="none"
		>
			<defs>
				<linearGradient id={gradientId} gradientUnits="userSpaceOnUse" x1="0" x2={W} y1="0" y2="0">
					<stop offset="0" stop-color="var(--brand-from)" />
					<stop offset="1" stop-color="var(--brand-to)" />
				</linearGradient>
			</defs>
			{#each chart.bars as bar (bar.key)}
				<g>
					<title>{bar.label}</title>
					{#if bar.path}<path d={bar.path} fill="url(#{gradientId})" />{/if}
					{#if bar.blocked > 0}
						<rect x={bar.x} y={bar.blockedY} width={bar.w} height={bar.blockedH} fill="var(--danger)" />
					{/if}
				</g>
			{/each}
		</svg>
		<div class="mt-1 flex justify-between text-xs text-muted-foreground">
			<span>24 h ago</span>
			<span class="flex items-center gap-3">
				<span class="flex items-center gap-1"><span class="bg-brand-gradient inline-block size-2.5 rounded-[2px]"></span>queries</span>
				<span class="flex items-center gap-1"><span class="inline-block size-2.5 rounded-[2px] bg-danger"></span>blocked</span>
			</span>
			<span>now</span>
		</div>
	</div>
{/if}
