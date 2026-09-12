<script lang="ts">
	import * as Dialog from "$lib/components/ui/dialog";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Label } from "$lib/components/ui/label";

	let {
		open = $bindable(false),
		editingIndex = null,
		v6Name = $bindable(""),
		v6Start = $bindable(""),
		v6End = $bindable(""),
		v6Addr = $bindable(""),
		v6Dns = $bindable(""),
		v6Lease = $bindable<number | "">(86400),
		v6BootFile = $bindable(""),
		globalV6LeaseTime = 86400,
		onSubmit = () => {},
	}: {
		open?: boolean;
		editingIndex?: number | null;
		v6Name?: string;
		v6Start?: string;
		v6End?: string;
		v6Addr?: string;
		v6Dns?: string;
		v6Lease?: number | "";
		v6BootFile?: string;
		globalV6LeaseTime?: number;
		onSubmit?: () => void;
	} = $props();
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="sm:max-w-lg">
		<Dialog.Header>
			<Dialog.Title>
				{editingIndex !== null ? "Edit IPv6 Address Scope" : "Add New IPv6 Address Scope"}
			</Dialog.Title>
			<Dialog.Description>
				Configure stateful IPv6 suffix range or static prefix allocation
			</Dialog.Description>
		</Dialog.Header>

		<div class="flex flex-col gap-4 py-3">
			<!-- Name -->
			<div class="flex flex-col gap-1.5">
				<Label class="text-xs">Scope Name</Label>
				<Input bind:value={v6Name} placeholder="IPv6 IoT Pool" class="text-xs" />
			</div>

			<!-- Suffix Range -->
			<div class="grid grid-cols-2 gap-3">
				<div class="flex flex-col gap-1.5">
					<Label class="text-xs">Start Suffix *</Label>
					<Input
						bind:value={v6Start}
						placeholder="::100"
						class="font-mono text-xs"
					/>
				</div>
				<div class="flex flex-col gap-1.5">
					<Label class="text-xs">End Suffix *</Label>
					<Input
						bind:value={v6End}
						placeholder="::1fff"
						class="font-mono text-xs"
					/>
				</div>
			</div>

			<!-- Static CIDR Address -->
			<div class="flex flex-col gap-1.5">
				<Label class="text-xs">Static Prefix / CIDR (Optional)</Label>
				<Input
					bind:value={v6Addr}
					placeholder="fd00:abcd::/64 (leave empty to derive from interface)"
					class="font-mono text-xs"
				/>
			</div>

			<!-- Lease Duration & Custom DNS -->
			<div class="grid grid-cols-2 gap-3">
				<div class="flex flex-col gap-1.5">
					<Label class="text-xs">Lease Duration (seconds)</Label>
					<Input
						type="number"
						bind:value={v6Lease}
						placeholder={String(globalV6LeaseTime)}
						class="font-mono text-xs"
					/>
				</div>
				<div class="flex flex-col gap-1.5">
					<Label class="text-xs">Custom DNS (comma-sep)</Label>
					<Input
						bind:value={v6Dns}
						placeholder="2606:4700:4700::1111"
						class="font-mono text-xs"
					/>
				</div>
			</div>
		</div>

		<Dialog.Footer>
			<Button variant="outline" onclick={() => { open = false; }}>
				Cancel
			</Button>
			<Button onclick={onSubmit}>
				{editingIndex !== null ? "Update Scope" : "Add Scope"}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
