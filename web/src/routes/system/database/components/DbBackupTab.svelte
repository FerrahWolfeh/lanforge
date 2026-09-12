<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Button } from "$lib/components/ui/button";
	import { Label } from "$lib/components/ui/label";
	import { Switch } from "$lib/components/ui/switch";
	import FileDownIcon from "@lucide/svelte/icons/file-down";
	import FileUpIcon from "@lucide/svelte/icons/file-up";
	import FileTextIcon from "@lucide/svelte/icons/file-text";
	import DownloadIcon from "@lucide/svelte/icons/download";
	import UploadIcon from "@lucide/svelte/icons/upload";
	import CheckIcon from "@lucide/svelte/icons/check";

	let {
		exporting = false,
		exportingToml = false,
		importing = false,
		selectedFile = null,
		importOverwrite = $bindable(false),
		importFileInput = $bindable<HTMLInputElement | null>(null),
		formatBytes = (b: number) => `${b} B`,
		onExportToml = () => {},
		onExportJson = () => {},
		onFileSelected = () => {},
		onImport = () => {},
	}: {
		exporting?: boolean;
		exportingToml?: boolean;
		importing?: boolean;
		selectedFile?: File | null;
		importOverwrite?: boolean;
		importFileInput?: HTMLInputElement | null;
		formatBytes?: (b: number) => string;
		onExportToml?: () => void;
		onExportJson?: () => void;
		onFileSelected?: (e: Event) => void;
		onImport?: () => void;
	} = $props();
</script>

<div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
	<!-- Export Configuration Card -->
	<Card.Root>
		<Card.Header>
			<Card.Title class="flex items-center gap-2 text-base font-semibold">
				<FileDownIcon class="size-5 text-primary" />
				Export System Configuration
			</Card.Title>
			<Card.Description class="text-xs leading-relaxed mt-1">
				Generate and download consolidated configuration as a directly deployable lanforge.toml file or an aggregated JSON persistence snapshot.
			</Card.Description>
		</Card.Header>
		<Card.Content class="space-y-4">
			<div class="rounded-lg border bg-muted/30 p-3 space-y-2 text-xs">
				<div class="font-medium text-foreground">
					Included Subsystems:
				</div>
				<ul class="grid grid-cols-1 sm:grid-cols-2 gap-1.5 text-muted-foreground">
					<li class="flex items-center gap-1.5">
						<CheckIcon class="size-3.5 text-emerald-500" />
						Static Hosts & Leases
					</li>
					<li class="flex items-center gap-1.5">
						<CheckIcon class="size-3.5 text-emerald-500" />
						DHCPv4 & DHCPv6 Pools
					</li>
					<li class="flex items-center gap-1.5">
						<CheckIcon class="size-3.5 text-emerald-500" />
						DHCP Options & TFTP
					</li>
					<li class="flex items-center gap-1.5">
						<CheckIcon class="size-3.5 text-emerald-500" />
						DNS Rewrites & Upstreams
					</li>
					<li class="flex items-center gap-1.5">
						<CheckIcon class="size-3.5 text-emerald-500" />
						Adblock Rules & Sources
					</li>
					<li class="flex items-center gap-1.5">
						<CheckIcon class="size-3.5 text-emerald-500" />
						Reverse DNS Resolvers
					</li>
					<li class="flex items-center gap-1.5">
						<CheckIcon class="size-3.5 text-emerald-500" />
						IPv6 RA Prefixes & Options
					</li>
					<li class="flex items-center gap-1.5">
						<CheckIcon class="size-3.5 text-emerald-500" />
						PPPoE WAN Concentrator
					</li>
				</ul>
			</div>

			<div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
				<Button
					variant="default"
					class="gap-2 text-xs"
					onclick={onExportToml}
					disabled={exportingToml}
				>
					<FileTextIcon class={exportingToml ? "animate-spin size-4" : "size-4"} />
					{exportingToml ? "Generating TOML..." : "Download lanforge.toml"}
				</Button>

				<Button
					variant="outline"
					class="gap-2 text-xs"
					onclick={onExportJson}
					disabled={exporting}
				>
					<DownloadIcon class={exporting ? "animate-spin size-4" : "size-4"} />
					{exporting ? "Generating Snapshot..." : "Download JSON Snapshot"}
				</Button>
			</div>
		</Card.Content>
	</Card.Root>

	<!-- Import Configuration Card -->
	<Card.Root>
		<Card.Header>
			<Card.Title class="flex items-center gap-2 text-base font-semibold">
				<FileUpIcon class="size-5 text-primary" />
				Restore System Configuration
			</Card.Title>
			<Card.Description class="text-xs leading-relaxed mt-1">
				Apply an exported JSON configuration file to populate or restore daemon persistence tables.
			</Card.Description>
		</Card.Header>
		<Card.Content class="space-y-4">
			<div class="space-y-2">
				<Label for="config-file-upload" class="text-xs font-medium">Select JSON File</Label>
				<input
					id="config-file-upload"
					type="file"
					accept=".json,application/json"
					bind:this={importFileInput}
					onchange={onFileSelected}
					class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-xs shadow-sm file:border-0 file:bg-transparent file:text-xs file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring cursor-pointer"
				/>
				{#if selectedFile}
					<p class="text-xs text-muted-foreground">
						Selected: <span class="font-medium text-foreground">{selectedFile.name}</span>
						({formatBytes(selectedFile.size)})
					</p>
				{/if}
			</div>

			<div class="flex items-center justify-between rounded-lg border p-3">
				<div class="space-y-0.5">
					<Label class="text-xs font-medium cursor-pointer" for="overwrite-switch">
						Overwrite Existing Records
					</Label>
					<p class="text-[11px] text-muted-foreground">
						Purges current records before importing instead of merging entities.
					</p>
				</div>
				<Switch id="overwrite-switch" bind:checked={importOverwrite} />
			</div>

			<Button
				variant="default"
				class="w-full gap-2 text-xs"
				onclick={onImport}
				disabled={importing || !selectedFile}
			>
				<UploadIcon class={importing ? "animate-spin size-4" : "size-4"} />
				{importing ? "Restoring Configuration..." : "Apply Configuration"}
			</Button>
		</Card.Content>
	</Card.Root>
</div>
