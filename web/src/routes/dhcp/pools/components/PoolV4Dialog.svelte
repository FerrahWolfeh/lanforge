<script lang="ts">
	import * as Dialog from "$lib/components/ui/dialog";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Label } from "$lib/components/ui/label";
	import { Separator } from "$lib/components/ui/separator";

	let {
		open = $bindable(false),
		editingIndex = null,
		v4Name = $bindable(""),
		v4Start = $bindable(""),
		v4End = $bindable(""),
		v4Router = $bindable(""),
		v4SubnetMask = $bindable(""),
		v4Dns = $bindable(""),
		v4Lease = $bindable<number | "">(86400),
		v4BootFile = $bindable(""),
		v4TftpServer = $bindable(""),
		globalV4Router = "",
		globalV4SubnetMask = "255.255.255.0",
		globalV4LeaseTime = 86400,
		onSubmit = () => {},
	}: {
		open?: boolean;
		editingIndex?: number | null;
		v4Name?: string;
		v4Start?: string;
		v4End?: string;
		v4Router?: string;
		v4SubnetMask?: string;
		v4Dns?: string;
		v4Lease?: number | "";
		v4BootFile?: string;
		v4TftpServer?: string;
		globalV4Router?: string;
		globalV4SubnetMask?: string;
		globalV4LeaseTime?: number;
		onSubmit?: () => void;
	} = $props();
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="sm:max-w-lg">
		<Dialog.Header>
			<Dialog.Title>
				{editingIndex !== null ? "Edit IPv4 Address Scope" : "Add New IPv4 Address Scope"}
			</Dialog.Title>
			<Dialog.Description>
				Define the IP range and optional network overrides for this scope
			</Dialog.Description>
		</Dialog.Header>

		<div class="flex flex-col gap-4 py-3">
			<!-- Name -->
			<div class="flex flex-col gap-1.5">
				<Label class="text-xs">Scope Name / Label</Label>
				<Input bind:value={v4Name} placeholder="LAN Main Pool" class="text-xs" />
			</div>

			<!-- Start & End Range -->
			<div class="grid grid-cols-2 gap-3">
				<div class="flex flex-col gap-1.5">
					<Label class="text-xs">Start IP Address *</Label>
					<Input
						bind:value={v4Start}
						placeholder="192.168.1.100"
						class="font-mono text-xs"
					/>
				</div>
				<div class="flex flex-col gap-1.5">
					<Label class="text-xs">End IP Address *</Label>
					<Input
						bind:value={v4End}
						placeholder="192.168.1.200"
						class="font-mono text-xs"
					/>
				</div>
			</div>

			<!-- Gateway & Subnet Mask -->
			<div class="grid grid-cols-2 gap-3">
				<div class="flex flex-col gap-1.5">
					<Label class="text-xs">Gateway Override (Option 3)</Label>
					<Input
						bind:value={v4Router}
						placeholder={globalV4Router || "Inherit global"}
						class="font-mono text-xs"
					/>
				</div>
				<div class="flex flex-col gap-1.5">
					<Label class="text-xs">Subnet Mask Override</Label>
					<Input
						bind:value={v4SubnetMask}
						placeholder={globalV4SubnetMask}
						class="font-mono text-xs"
					/>
				</div>
			</div>

			<!-- Lease Duration & Custom DNS -->
			<div class="grid grid-cols-2 gap-3">
				<div class="flex flex-col gap-1.5">
					<Label class="text-xs">Lease Duration (seconds)</Label>
					<Input
						type="number"
						bind:value={v4Lease}
						placeholder={String(globalV4LeaseTime)}
						class="font-mono text-xs"
					/>
				</div>
				<div class="flex flex-col gap-1.5">
					<Label class="text-xs">Custom DNS (comma-sep)</Label>
					<Input
						bind:value={v4Dns}
						placeholder="192.168.1.1, 1.1.1.1"
						class="font-mono text-xs"
					/>
				</div>
			</div>

			<Separator class="my-1" />

			<!-- Netboot / PXE Overrides -->
			<div class="flex flex-col gap-2">
				<span class="text-xs font-semibold text-foreground">
					PXE Netboot Overrides (Optional)
				</span>
				<div class="grid grid-cols-2 gap-3">
					<div class="flex flex-col gap-1.5">
						<Label class="text-[11px]">Next Server / TFTP (Option 66)</Label>
						<Input
							bind:value={v4TftpServer}
							placeholder="192.168.1.1"
							class="font-mono text-xs"
						/>
					</div>
					<div class="flex flex-col gap-1.5">
						<Label class="text-[11px]">Boot Filename (Option 67)</Label>
						<Input
							bind:value={v4BootFile}
							placeholder="ipxe.efi"
							class="font-mono text-xs"
						/>
					</div>
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
