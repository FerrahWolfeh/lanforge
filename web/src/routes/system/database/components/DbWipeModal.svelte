<script lang="ts">
	import * as AlertDialog from "$lib/components/ui/alert-dialog";
	import { Input } from "$lib/components/ui/input";
	import AlertTriangleIcon from "@lucide/svelte/icons/triangle-alert";

	let {
		open = $bindable(false),
		wiping = false,
		onConfirm = () => {},
	}: {
		open?: boolean;
		wiping?: boolean;
		onConfirm?: () => void;
	} = $props();

	let wipeConfirmText = $state("");
</script>

<AlertDialog.Root bind:open>
	<AlertDialog.Content>
		<AlertDialog.Header>
			<AlertDialog.Title class="flex items-center gap-2 text-destructive">
				<AlertTriangleIcon class="size-5" />
				Confirm Complete Database Wipe
			</AlertDialog.Title>
			<AlertDialog.Description class="space-y-2 text-xs">
				<p>
					This action will cascade-delete all stored static devices, active DHCP lease reservations, DNS custom rewrites, upstreams, adblock lists, and API access tokens.
				</p>
				<p class="font-semibold text-foreground">
					To proceed, type <span class="font-mono text-destructive underline">wipe</span> into the box below:
				</p>
			</AlertDialog.Description>
		</AlertDialog.Header>
		<div class="py-2">
			<Input
				bind:value={wipeConfirmText}
				placeholder="Type 'wipe' to confirm"
				class="font-mono text-sm"
			/>
		</div>
		<AlertDialog.Footer>
			<AlertDialog.Cancel onclick={() => { wipeConfirmText = ""; open = false; }}>
				Cancel
			</AlertDialog.Cancel>
			<AlertDialog.Action
				class="bg-destructive text-destructive-foreground hover:bg-destructive/90"
				onclick={() => {
					onConfirm();
					wipeConfirmText = "";
				}}
				disabled={wipeConfirmText !== "wipe" || wiping}
			>
				{wiping ? "Wiping Database..." : "Permanently Wipe"}
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
