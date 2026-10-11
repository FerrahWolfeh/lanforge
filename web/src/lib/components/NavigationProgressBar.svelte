<script lang="ts">
	import { navigating } from "$app/state";

	let visible = $state(false);
	let progress = $state(0);
	let timer: ReturnType<typeof setTimeout> | null = null;
	let interval: ReturnType<typeof setInterval> | null = null;

	$effect(() => {
		if (navigating.to) {
			visible = true;
			progress = 18;
			if (interval) clearInterval(interval);
			interval = setInterval(() => {
				if (progress < 85) {
					progress += Math.max(1, (85 - progress) * 0.18);
				}
			}, 60);
		} else if (visible) {
			if (interval) {
				clearInterval(interval);
				interval = null;
			}
			progress = 100;
			timer = setTimeout(() => {
				visible = false;
				progress = 0;
			}, 220);
		}

		return () => {
			if (timer) clearTimeout(timer);
			if (interval) clearInterval(interval);
		};
	});
</script>

{#if visible}
	<div
		class="pointer-events-none absolute top-0 left-0 right-0 z-50 h-[2.5px] overflow-hidden bg-transparent"
		role="progressbar"
		aria-valuemin="0"
		aria-valuemax="100"
		aria-valuenow={Math.round(progress)}
	>
		<div
			class="h-full bg-gradient-to-r from-primary via-indigo-500 to-sky-400 shadow-[0_0_12px_rgba(99,102,241,0.8)] transition-all duration-150 ease-out"
			style="width: {progress}%; opacity: {progress === 100 ? 0 : 1};"
		></div>
	</div>
{/if}
