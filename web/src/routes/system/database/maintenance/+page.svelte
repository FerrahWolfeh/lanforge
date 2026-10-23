<script lang="ts">
	import { toast } from "svelte-sonner";
	import {
		dbPrune,
		dbLogClean,
		dbReset,
	} from "$lib/api/client";
	import DbMaintenanceTab from "../components/DbMaintenanceTab.svelte";
	import DbWipeModal from "../components/DbWipeModal.svelte";
	import { dbState, formatTimeAgo } from "../dbState.svelte";

	let pruning = $state(false);
	let logCleaning = $state(false);
	let wiping = $state(false);
	let wipeDialogOpen = $state(false);

	let lastPruneTime = $state<number | null>(null);
	let lastLogCleanTime = $state<number | null>(null);

	async function handlePrune() {
		pruning = true;
		try {
			await dbPrune();
			lastPruneTime = Math.floor(Date.now() / 1000);
			toast.success("Zombie devices pruned", {
				description: "Purged inactive dynamic devices with no hostname nor active lease.",
			});
			await dbState.loadAll(true);
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
				description: "Log buffers and temporary query history truncated.",
			});
			await dbState.loadAll(true);
		} catch (e: any) {
			toast.error("Log clean failed", {
				description: e?.message || "Internal server error",
			});
		} finally {
			logCleaning = false;
		}
	}

	async function handleReset() {
		wiping = true;
		try {
			await dbReset();
			toast.success("Database reset complete", {
				description: "All persistent state and transient caches were purged.",
			});
			wipeDialogOpen = false;
			await dbState.loadAll(true);
		} catch (e: any) {
			toast.error("Reset failed", {
				description: e?.message || "Internal server error",
			});
		} finally {
			wiping = false;
		}
	}
</script>

<DbMaintenanceTab
	{pruning}
	{logCleaning}
	{lastPruneTime}
	{lastLogCleanTime}
	{formatTimeAgo}
	onPrune={handlePrune}
	onLogClean={handleLogClean}
	onOpenWipeDialog={() => (wipeDialogOpen = true)}
/>

<!-- Wipe Confirmation Dialog -->
<DbWipeModal
	bind:open={wipeDialogOpen}
	{wiping}
	onConfirm={handleReset}
/>
