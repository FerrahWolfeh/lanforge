<script lang="ts">
	import { toggleMode } from "mode-watcher";
	import { Button } from "$lib/components/ui/button";
	import SunIcon from "@lucide/svelte/icons/sun";
	import MoonIcon from "@lucide/svelte/icons/moon";

	function handleToggle() {
		if (typeof document !== "undefined" && "startViewTransition" in document) {
			(document as Document & { startViewTransition: (cb: () => void) => void }).startViewTransition(() => {
				toggleMode();
			});
		} else {
			toggleMode();
		}
	}
</script>

<Button
	variant="ghost"
	size="icon"
	class="relative size-9 rounded-lg transition-transform hover:scale-105 active:scale-95"
	onclick={handleToggle}
	aria-label="Toggle dark/light theme"
>
	<SunIcon class="size-4 rotate-0 scale-100 transition-all duration-300 dark:-rotate-90 dark:scale-0" />
	<MoonIcon class="absolute size-4 rotate-90 scale-0 transition-all duration-300 dark:rotate-0 dark:scale-100" />
	<span class="sr-only">Toggle dark/light theme</span>
</Button>
