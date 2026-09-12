<script lang="ts">
	import DbInventoryTab from "./components/DbInventoryTab.svelte";
	import { dbState } from "./dbState.svelte";
</script>

<DbInventoryTab
	inventoryItems={dbState.inventoryItems}
	totalStoredEntities={dbState.totalStoredEntities}
	isInMemory={dbState.isInMemory}
/>
