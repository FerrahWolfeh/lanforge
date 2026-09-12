<script lang="ts">
	import * as AlertDialog from "$lib/components/ui/alert-dialog";
	import AlertTriangleIcon from "@lucide/svelte/icons/triangle-alert";

	let {
		open = $bindable(false),
		onConfirm = () => {},
	}: {
		open?: boolean;
		onConfirm?: () => void;
	} = $props();
</script>

<AlertDialog.Root bind:open>
	<AlertDialog.Content class="max-w-md">
		<AlertDialog.Header>
			<AlertDialog.Title class="flex items-center gap-2 text-amber-600 dark:text-amber-400">
				<AlertTriangleIcon class="size-5 text-amber-500" />
				Experimental eBPF Architecture
			</AlertDialog.Title>
			<AlertDialog.Description class="flex flex-col gap-2 text-left pt-2 text-xs leading-relaxed">
				<p>
					eBPF Fast-Path bypasses the standard Linux networking stack using TC filters and Generic XDP.
				</p>
				<p>
					While offering ultra-low CPU utilization and higher line rates, it requires an up-to-date Linux Kernel (5.15+) and specialized network driver hooks. If your kernel lacks BPF features, the daemon will automatically fallback to standard kernel mode.
				</p>
			</AlertDialog.Description>
		</AlertDialog.Header>
		<AlertDialog.Footer>
			<AlertDialog.Cancel onclick={() => (open = false)}>
				Cancel
			</AlertDialog.Cancel>
			<AlertDialog.Action
				onclick={() => {
					onConfirm();
					open = false;
				}}
			>
				I understand, enable eBPF
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
