<script lang="ts">
	let {
		data = [10, 12, 11, 14, 13, 16, 15, 18, 17, 20],
		color = "#38bdf8",
		height = 36,
		class: className = "",
	}: {
		data?: number[];
		color?: string;
		height?: number;
		class?: string;
	} = $props();

	const uid = $props.id();
	const gradId = `sparkline-grad-${uid.replace(/:/g, "")}`;

	const normalized = $derived.by(() => {
		const pts = data.length > 0 ? data : [10, 12, 14, 13, 15, 16];
		const min = Math.min(...pts);
		const max = Math.max(...pts);
		const range = max - min || 1;
		const width = 120;
		const h = height;
		const padding = 3;

		const coords = pts.map((val, i) => {
			const x = (i / (pts.length - 1 || 1)) * width;
			const y = h - padding - ((val - min) / range) * (h - padding * 2);
			return { x, y };
		});

		// Build smooth cubic bezier SVG path
		let linePath = `M ${coords[0].x.toFixed(1)} ${coords[0].y.toFixed(1)}`;
		for (let i = 1; i < coords.length; i++) {
			const prev = coords[i - 1];
			const curr = coords[i];
			const cpx1 = prev.x + (curr.x - prev.x) / 2;
			const cpy1 = prev.y;
			const cpx2 = prev.x + (curr.x - prev.x) / 2;
			const cpy2 = curr.y;
			linePath += ` C ${cpx1.toFixed(1)} ${cpy1.toFixed(1)}, ${cpx2.toFixed(1)} ${cpy2.toFixed(1)}, ${curr.x.toFixed(1)} ${curr.y.toFixed(1)}`;
		}

		const areaPath = `${linePath} L ${coords[coords.length - 1].x.toFixed(1)} ${h} L ${coords[0].x.toFixed(1)} ${h} Z`;

		return { linePath, areaPath, width, height: h };
	});
</script>

<div class={["w-full overflow-hidden flex items-end", className].join(" ")}>
	<svg
		viewBox="0 0 {normalized.width} {normalized.height}"
		class="w-full overflow-visible"
		style="height: {height}px"
		preserveAspectRatio="none"
	>
		<defs>
			<linearGradient id={gradId} x1="0%" y1="0%" x2="0%" y2="100%">
				<stop offset="0%" stop-color={color} stop-opacity="0.35" />
				<stop offset="100%" stop-color={color} stop-opacity="0.0" />
			</linearGradient>
		</defs>
		<path d={normalized.areaPath} fill="url(#{gradId})" />
		<path
			d={normalized.linePath}
			fill="none"
			stroke={color}
			stroke-width="1.75"
			stroke-linecap="round"
			stroke-linejoin="round"
		/>
	</svg>
</div>
