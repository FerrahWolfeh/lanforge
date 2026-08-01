<script lang="ts">
	import "./layout.css";
	import favicon from "$lib/assets/favicon.svg";
	import AppSidebar from "$lib/components/AppSidebar.svelte";
	import Topbar from "$lib/components/Topbar.svelte";
	import * as Sidebar from "$lib/components/ui/sidebar";
	import { Toaster } from "$lib/components/ui/sonner";
	import { ModeWatcher } from "mode-watcher";
	import { auth } from "$lib/stores/auth.svelte";
	import { status } from "$lib/api/client";
	import { onMount } from "svelte";
	import { page } from "$app/stores";

	let { children } = $props();
	let uptime = $state(0);

	const isLoginPage = $derived($page.url.pathname === "/login");

	onMount(() => {
		// Poll daemon uptime every 30s
		async function pollStatus() {
			try {
				const s = await status();
				uptime = s.uptime_secs;
			} catch {
				// daemon unreachable — leave uptime as-is
			}
		}

		if (!isLoginPage) {
			pollStatus();
			const interval = setInterval(pollStatus, 30_000);
			return () => {
				clearInterval(interval);
			};
		}
	});
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
	<title>Lanforge</title>
</svelte:head>

<ModeWatcher defaultMode="system" />

{#if isLoginPage}
	{@render children()}
{:else}
	<Sidebar.Provider>
		<AppSidebar />
		<Sidebar.Inset>
			<Topbar {uptime} />
			<main class="flex flex-1 flex-col gap-6 p-6">
				{@render children()}
			</main>
		</Sidebar.Inset>
	</Sidebar.Provider>
{/if}

<Toaster richColors />
