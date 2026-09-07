<script lang="ts">
	import * as Dialog from "$lib/components/ui/dialog";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Label } from "$lib/components/ui/label";
	import { Badge } from "$lib/components/ui/badge";
	import * as Select from "$lib/components/ui/select";
	import * as Tabs from "$lib/components/ui/tabs";
	import ArrowRightLeftIcon from "@lucide/svelte/icons/arrow-right-left";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import LaptopIcon from "@lucide/svelte/icons/laptop";
	import ServerIcon from "@lucide/svelte/icons/server";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import { toast } from "svelte-sonner";
	import { listDevices } from "$lib/api/client";
	import {
		type RewriteRule,
		type DnsRecordType,
		type DeviceEntry,
		formatRewriteAnswer,
	} from "$lib/api/types";

	import DeviceCombobox from "$lib/components/DeviceCombobox.svelte";

	let {
		open = $bindable(false),
		rule = null,
		onSave = async (rule: any) => {},
	}: {
		open: boolean;
		rule?: RewriteRule | null;
		onSave?: (rule: any) => Promise<void>;
	} = $props();

	let mode = $state<"static" | "device" | "service">("static");
	let domain = $state("");
	let rtype = $state<DnsRecordType>("A");
	let saving = $state(false);

	// Mode 1: Static Target
	let staticAnswer = $state("");

	// Mode 2: Dynamic Device Target (dev:)
	let knownDevices = $state<DeviceEntry[]>([]);
	let loadingDevices = $state(false);
	let selectedDeviceIdentifier = $state("");
	let deviceFallbackIp = $state("");

	// Mode 3: Dynamic SRV Target (srv:)
	let srvService = $state("_plex");
	let srvProtocol = $state("_tcp");
	let srvDeviceIdentifier = $state("");
	let srvPort = $state<number>(32400);

	const RECORD_TYPES: DnsRecordType[] = [
		"A",
		"AAAA",
		"CNAME",
		"PTR",
		"TXT",
		"MX",
		"NS",
		"SOA",
		"SRV",
		"HTTPS",
		"SVCB",
	];

	async function fetchDevices() {
		loadingDevices = true;
		try {
			const res = await listDevices();
			if (res && res.devices) {
				knownDevices = res.devices;
			}
		} catch {
			// silent fallback
		} finally {
			loadingDevices = false;
		}
	}

	$effect(() => {
		if (open) {
			fetchDevices();
			if (rule) {
				domain = rule.domain;
				rtype = rule.rtype;
				const ans = formatRewriteAnswer(rule.answer);
				if (ans.startsWith("dev:") || rule.rtype === "DEVICE") {
					mode = "device";
					rtype = "DEVICE";
					const content = ans.startsWith("dev:") ? ans.slice(4) : ans;
					if (content.includes("|")) {
						const [devId, fb] = content.split("|");
						selectedDeviceIdentifier = devId;
						deviceFallbackIp = fb;
					} else {
						selectedDeviceIdentifier = content;
						deviceFallbackIp = "";
					}
				} else if (ans.startsWith("srv:") || rule.rtype === "SRV") {
					mode = "service";
					if (ans.startsWith("srv:")) {
						const parts = ans.slice(4).split(":");
						if (parts.length >= 4) {
							srvService = parts[0];
							srvProtocol = parts[1];
							srvPort = Number(parts[parts.length - 1]) || 80;
							srvDeviceIdentifier = parts
								.slice(2, parts.length - 1)
								.join(":");
						}
					}
				} else {
					mode = "static";
					staticAnswer = ans;
				}
			} else {
				// Reset form for new rule
				domain = "";
				rtype = "A";
				staticAnswer = "";
				mode = "static";
				selectedDeviceIdentifier = "";
				deviceFallbackIp = "";
				srvService = "_http";
				srvProtocol = "_tcp";
				srvDeviceIdentifier = "";
				srvPort = 80;
			}
		}
	});

	function buildFinalAnswer(): { answer: string; type: DnsRecordType } {
		if (mode === "device") {
			const devId = selectedDeviceIdentifier.trim();
			if (!devId) {
				throw new Error("Please select or enter a device identifier");
			}
			const fallback = deviceFallbackIp.trim();
			const ans = fallback ? `dev:${devId}|${fallback}` : `dev:${devId}`;
			return { answer: ans, type: "DEVICE" };
		}

		if (mode === "service") {
			const svc = srvService.trim() || "_service";
			const proto = srvProtocol.trim() || "_tcp";
			const dev = srvDeviceIdentifier.trim();
			if (!dev) {
				throw new Error(
					"Please specify a target device for SRV service",
				);
			}
			const port = srvPort || 80;
			return {
				answer: `srv:${svc}:${proto}:${dev}:${port}`,
				type: "SRV",
			};
		}

		const ans = staticAnswer.trim();
		if (!ans) {
			throw new Error(
				"Please specify an IP address or CNAME target domain",
			);
		}
		return { answer: ans, type: rtype };
	}

	async function handleSubmit() {
		const domClean = domain.trim().replace(/\.$/, "");
		if (!domClean) {
			toast.error("Please specify a domain pattern");
			return;
		}

		try {
			const { answer, type } = buildFinalAnswer();
			saving = true;

			const payload: RewriteRule = {
				id: rule?.id ?? null,
				domain: domClean,
				rtype: type,
				answer,
				resolved_ips: rule?.resolved_ips ?? null,
			};

			await onSave(payload);
			open = false;
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to save rewrite rule");
		} finally {
			saving = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content
		class="w-[95vw] max-w-lg sm:max-w-lg overflow-visible border shadow-lg"
	>
		<Dialog.Header class="space-y-1">
			<Dialog.Title
				class="text-base font-semibold flex items-center gap-2"
			>
				<ArrowRightLeftIcon class="h-5 w-5 text-primary" />
				{rule ? "Edit DNS Rewrite Rule" : "Add DNS Rewrite Rule"}
			</Dialog.Title>
			<Dialog.Description class="text-xs">
				Override DNS responses for specific domains, wildcards, or local
				LAN devices.
			</Dialog.Description>
		</Dialog.Header>

		<div class="space-y-4 py-2 text-xs">
			<!-- Domain Pattern Field -->
			<div class="space-y-1.5">
				<Label for="rewrite-domain" class="text-xs font-medium"
					>Domain Name / Pattern</Label
				>
				<Input
					id="rewrite-domain"
					type="text"
					placeholder="e.g. app.lan, *.home.arpa, or server.local"
					class="h-9 text-xs font-mono"
					bind:value={domain}
				/>
				<p class="text-[11px] text-muted-foreground">
					Supports exact domains (`app.lan`) or wildcard patterns
					(`*.home.arpa`).
				</p>
			</div>

			<!-- Target Mode Selector Tabs -->
			<Tabs.Root value={mode} onValueChange={(v) => (mode = v as any)}>
				<Tabs.List class="grid grid-cols-3 w-full h-9">
					<Tabs.Trigger value="static" class="text-xs gap-1">
						<GlobeIcon class="h-3.5 w-3.5" />
						Static Target
					</Tabs.Trigger>
					<Tabs.Trigger value="device" class="text-xs gap-1">
						<LaptopIcon class="h-3.5 w-3.5" />
						Device (dev:)
					</Tabs.Trigger>
					<Tabs.Trigger value="service" class="text-xs gap-1">
						<ServerIcon class="h-3.5 w-3.5" />
						SRV Service
					</Tabs.Trigger>
				</Tabs.List>

				<!-- Mode 1: Static Target -->
				<Tabs.Content value="static" class="space-y-3 pt-3">
					<div class="grid grid-cols-3 gap-2">
						<div class="col-span-1 space-y-1.5">
							<Label class="text-xs font-medium"
								>Record Type</Label
							>
							<Select.Root
								type="single"
								value={rtype}
								onValueChange={(val) =>
									(rtype = (val as DnsRecordType) ?? "A")}
							>
								<Select.Trigger class="h-9 text-xs">
									{rtype}
								</Select.Trigger>
								<Select.Content>
									{#each RECORD_TYPES as t (t)}
										<Select.Item value={t} class="text-xs"
											>{t}</Select.Item
										>
									{/each}
								</Select.Content>
							</Select.Root>
						</div>

						<div class="col-span-2 space-y-1.5">
							<Label
								for="static-target"
								class="text-xs font-medium"
								>IP Address / CNAME Target</Label
							>
							<Input
								id="static-target"
								type="text"
								placeholder="192.168.1.50, fd00::50, or alias.lan"
								class="h-9 text-xs font-mono"
								bind:value={staticAnswer}
							/>
						</div>
					</div>
				</Tabs.Content>

				<!-- Mode 2: Dynamic Device Target (dev:) -->
				<Tabs.Content value="device" class="space-y-3 pt-3">
					<div class="space-y-1.5">
						<Label class="text-xs font-medium"
							>Target LAN Device</Label
						>
						<DeviceCombobox
							bind:value={selectedDeviceIdentifier}
							devices={knownDevices}
							placeholder="Search or enter device hostname / MAC address..."
						/>
					</div>

					<div class="space-y-1.5">
						<Label for="device-fallback" class="text-xs font-medium"
							>Optional Fallback IP</Label
						>
						<Input
							id="device-fallback"
							type="text"
							placeholder="e.g. 192.168.1.100 (used if device is offline)"
							class="h-9 text-xs font-mono"
							bind:value={deviceFallbackIp}
						/>
					</div>

					<p class="text-[11px] text-muted-foreground">
						Creates a <code class="font-mono text-primary font-semibold">DEVICE</code> rewrite record. Lanforge dynamically resolves incoming DNS queries to the device's live IPv4 (<code class="font-mono">A</code>) and IPv6 (<code class="font-mono">AAAA</code>) addresses without needing static CNAME redirection.
					</p>
				</Tabs.Content>

				<!-- Mode 3: Dynamic SRV Service (srv:) -->
				<Tabs.Content value="service" class="space-y-3 pt-3">
					<div class="grid grid-cols-2 gap-2">
						<div class="space-y-1.5">
							<Label for="srv-name" class="text-xs font-medium"
								>Service Name</Label
							>
							<Input
								id="srv-name"
								type="text"
								placeholder="_plex, _http, _matrix"
								class="h-9 text-xs font-mono"
								bind:value={srvService}
							/>
						</div>

						<div class="space-y-1.5">
							<Label for="srv-proto" class="text-xs font-medium"
								>Protocol</Label
							>
							<Input
								id="srv-proto"
								type="text"
								placeholder="_tcp or _udp"
								class="h-9 text-xs font-mono"
								bind:value={srvProtocol}
							/>
						</div>
					</div>

					<div class="grid grid-cols-3 gap-2">
						<div class="col-span-2 space-y-1.5">
							<Label class="text-xs font-medium"
								>Target Device</Label
							>
							<DeviceCombobox
								bind:value={srvDeviceIdentifier}
								devices={knownDevices}
								placeholder="Select target device..."
							/>
						</div>

						<div class="col-span-1 space-y-1.5">
							<Label for="srv-port" class="text-xs font-medium"
								>Port</Label
							>
							<Input
								id="srv-port"
								type="number"
								placeholder="32400"
								class="h-9 text-xs font-mono"
								bind:value={srvPort}
							/>
						</div>
					</div>
				</Tabs.Content>
			</Tabs.Root>
		</div>

		<Dialog.Footer class="pt-3 gap-2 sm:gap-0">
			<Button
				variant="outline"
				size="sm"
				onclick={() => (open = false)}
				disabled={saving}
			>
				Cancel
			</Button>
			<Button
				size="sm"
				onclick={handleSubmit}
				disabled={saving}
				class="gap-2"
			>
				{#if saving}
					<RefreshCwIcon class="h-4 w-4 animate-spin" />
					Saving...
				{:else}
					{rule ? "Update Rule" : "Create Rewrite Rule"}
				{/if}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
