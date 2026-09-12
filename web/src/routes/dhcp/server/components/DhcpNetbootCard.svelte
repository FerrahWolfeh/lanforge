<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Input } from "$lib/components/ui/input";
	import { Label } from "$lib/components/ui/label";
	import { Button } from "$lib/components/ui/button";
	import HardDriveIcon from "@lucide/svelte/icons/hard-drive";
	import ExternalLinkIcon from "@lucide/svelte/icons/external-link";

	let {
		v4TftpServer = $bindable(""),
		v4BootFile = $bindable(""),
		v6BootFile = $bindable(""),
	}: {
		v4TftpServer?: string;
		v4BootFile?: string;
		v6BootFile?: string;
	} = $props();
</script>

<Card.Root class="border-border/80 shadow-sm overflow-hidden">
	<Card.Header class="bg-muted/20 border-b pb-4">
		<div class="flex items-center justify-between">
			<div class="flex items-center gap-2.5">
				<HardDriveIcon class="size-5 text-amber-500" />
				<div>
					<Card.Title class="text-base font-bold">Network Boot &amp; TFTP Parameters</Card.Title>
					<Card.Description class="text-xs">
						Default PXE and UEFI HTTP netboot options (Option 66, 67, 59)
					</Card.Description>
				</div>
			</div>
			<Button
				variant="outline"
				size="sm"
				href="/tftp"
				class="h-7 text-xs gap-1.5"
			>
				<span>TFTP Server Menu</span>
				<ExternalLinkIcon class="size-3" />
			</Button>
		</div>
	</Card.Header>

	<Card.Content class="p-4 sm:p-6">
		<div class="grid grid-cols-1 md:grid-cols-3 gap-4">
			<div class="flex flex-col gap-1.5">
				<Label for="v4-tftp-server" class="text-xs font-semibold">
					Next-Server / siaddr (Option 66)
				</Label>
				<Input
					id="v4-tftp-server"
					bind:value={v4TftpServer}
					placeholder="e.g. 10.0.0.1"
					class="font-mono text-xs"
				/>
				<p class="text-[11px] text-muted-foreground">
					TFTP server IP advertised to PXE netboot clients.
				</p>
			</div>

			<div class="flex flex-col gap-1.5">
				<Label for="v4-boot-file" class="text-xs font-semibold">
					Default IPv4 Boot File (Option 67)
				</Label>
				<Input
					id="v4-boot-file"
					bind:value={v4BootFile}
					placeholder="ipxe.efi, pxelinux.0"
					class="font-mono text-xs"
				/>
				<p class="text-[11px] text-muted-foreground">
					Initial Network Bootstrap Program (NBP) file.
				</p>
			</div>

			<div class="flex flex-col gap-1.5">
				<Label for="v6-boot-file" class="text-xs font-semibold">
					Default IPv6 Boot URL (Option 59)
				</Label>
				<Input
					id="v6-boot-file"
					bind:value={v6BootFile}
					placeholder="tftp://[fd00::1]/ipxe.efi"
					class="font-mono text-xs"
				/>
				<p class="text-[11px] text-muted-foreground">
					DHCPv6 network bootloader URL.
				</p>
			</div>
		</div>
	</Card.Content>
</Card.Root>
