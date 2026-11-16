<script lang="ts">
	import DbInventoryTab from "./components/DbInventoryTab.svelte";
	import { dbState } from "./dbState.svelte";
</script>

<DbInventoryTab
	inventoryItems={dbState.inventoryItems}
	loading={dbState.loading}
	isInMemory={dbState.isInMemory}
/>
