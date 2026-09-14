<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Label } from "$lib/components/ui/label";
	import { Separator } from "$lib/components/ui/separator";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import CheckIcon from "@lucide/svelte/icons/check";
	import { toast } from "svelte-sonner";

	let {
		loading = false,
		dhcpV4TftpServer = $bindable(""),
		dhcpV4BootFile = $bindable(""),
		dhcpV6BootFile = $bindable(""),
		lanIpv4 = null,
		onUseLanforgeIp
	}: {
		loading: boolean;
		dhcpV4TftpServer: string;
		dhcpV4BootFile: string;
		dhcpV6BootFile: string;
		lanIpv4?: string | null;
		onUseLanforgeIp: () => void;
	} = $props();

	const BOOTLOADER_PRESETS = [
		{
			name: "iPXE UEFI",
			file: "ipxe.efi",
			desc: "Modern UEFI network bootloader with HTTP/SAN support",
		},
		{
			name: "Syslinux BIOS",
			file: "pxelinux.0",
			desc: "Classic BIOS PXELINUX bootloader",
		},
		{
			name: "SNP Universal",
			file: "snponly.efi",
			desc: "UEFI Simple Network Protocol driver",
		},
		{
			name: "UNDI Legacy",
			file: "undionly.kpxe",
			desc: "Legacy BIOS chainloader",
		},
	];

	function applyPreset(file: string) {
		dhcpV4BootFile = file;
		dhcpV6BootFile = file;
		toast.success(`Boot filename set to ${file}`);
	}
</script>

<Card.Root class="flex flex-col">
	<Card.Header class="pb-4 border-b border-border/50">
		<div class="flex items-center justify-between">
			<div class="flex items-center gap-2">
				<NetworkIcon class="size-4 text-sky-400" />
				<Card.Title class="text-base">DHCP PXE Boot Integration</Card.Title>
			</div>
			<Badge variant="outline" class="font-mono text-[10px]">Option 66 / 67</Badge>
		</div>
		<Card.Description>
			Synchronize DHCP announcements so PXE/UEFI clients automatically bootstrap from this TFTP server
		</Card.Description>
	</Card.Header>

	<Card.Content class="flex flex-col gap-5 p-5">
		{#if loading}
			<div class="flex flex-col gap-4">
				<Skeleton class="h-10 w-full" />
				<Skeleton class="h-10 w-full" />
				<Skeleton class="h-10 w-full" />
			</div>
		{:else}
			<!-- Option 66: TFTP Server Address -->
			<div class="flex flex-col gap-2">
				<div class="flex items-center justify-between">
					<Label class="text-xs font-medium">
						DHCPv4 Next Server / TFTP Server (Option 66)
					</Label>
					{#if lanIpv4}
						<Button
							variant="ghost"
							size="sm"
							class="h-6 text-[11px] text-primary px-2 py-0 cursor-pointer"
							onclick={onUseLanforgeIp}
						>
							<ZapIcon class="size-3 mr-1" />
							Use Lanforge IP ({lanIpv4})
						</Button>
					{/if}
				</div>
				<Input
					bind:value={dhcpV4TftpServer}
					placeholder="192.168.1.1 (leave blank to omit)"
					class="font-mono text-xs"
				/>
				<span class="text-[11px] text-muted-foreground">
					Announced in DHCP OFFER and ACK packets as Option 66 (sname / siaddr target).
				</span>
			</div>

			<!-- Option 67: Boot Filename -->
			<div class="flex flex-col gap-2">
				<div class="flex items-center justify-between">
					<Label class="text-xs font-medium">
						DHCPv4 Boot Filename (Option 67)
					</Label>
					<span class="text-[11px] text-muted-foreground font-mono">file parameter</span>
				</div>
				<Input
					bind:value={dhcpV4BootFile}
					placeholder="ipxe.efi, pxelinux.0, bootx64.efi..."
					class="font-mono text-xs"
				/>
			</div>

			<!-- DHCPv6 Boot File -->
			<div class="flex flex-col gap-2">
				<div class="flex items-center justify-between">
					<Label class="text-xs font-medium">
						DHCPv6 Boot URL / Filename (Option 59)
					</Label>
					<Badge variant="outline" class="text-[9px] font-mono">IPv6 RFC 5970</Badge>
				</div>
				<Input
					bind:value={dhcpV6BootFile}
					placeholder="tftp://[2001:db8::1]/ipxe.efi or ipxe.efi"
					class="font-mono text-xs"
				/>
			</div>

			<Separator class="my-1" />

			<!-- Bootloader Presets -->
			<div class="flex flex-col gap-2.5">
				<span class="text-xs font-semibold text-foreground uppercase tracking-wider">
					Popular Netboot Bootloaders
				</span>

				<div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
					{#each BOOTLOADER_PRESETS as preset (preset.file)}
						<button
							type="button"
							class={[
								"flex flex-col items-start gap-1 rounded-lg border p-2.5 text-left transition-all cursor-pointer",
								dhcpV4BootFile === preset.file
									? "border-primary bg-primary/10 text-foreground"
									: "border-border/60 bg-muted/20 hover:bg-muted/40 hover:border-zinc-700 text-muted-foreground",
							].join(" ")}
							onclick={() => applyPreset(preset.file)}
						>
							<div class="flex w-full items-center justify-between">
								<span class="text-xs font-semibold text-foreground">
									{preset.name}
								</span>
								{#if dhcpV4BootFile === preset.file}
									<CheckIcon class="size-3.5 text-primary" />
								{/if}
							</div>
							<span class="font-mono text-[11px] text-emerald-400">
								{preset.file}
							</span>
							<span class="text-[10px] leading-tight text-muted-foreground">
								{preset.desc}
							</span>
						</button>
					{/each}
				</div>
			</div>
		{/if}
	</Card.Content>
</Card.Root>
