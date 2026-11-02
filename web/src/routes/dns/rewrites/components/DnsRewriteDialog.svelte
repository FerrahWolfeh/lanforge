<script lang="ts">
	import * as Dialog from "$lib/components/ui/dialog";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Label } from "$lib/components/ui/label";
	import * as Select from "$lib/components/ui/select";
	import * as Tabs from "$lib/components/ui/tabs";
	import ArrowRightLeftIcon from "@lucide/svelte/icons/arrow-right-left";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import LaptopIcon from "@lucide/svelte/icons/laptop";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import { toast } from "svelte-sonner";
	import {
		dnsRewriteAdd,
		dnsRewriteList,
		dnsRewriteRemove,
		listDevices,
	} from "$lib/api/client";
	import {
		type RewriteRule,
		type DnsRecordType,
		type DeviceEntry,
		formatRewriteAnswer,
		splitDeviceAnswer,
	} from "$lib/api/types";

	import DeviceCombobox from "$lib/components/DeviceCombobox.svelte";

	// `group` is the rule being edited: one static rule, or every rule of one device answer
	// (a device keeps one rule per fallback). Empty when adding, optionally from `prefill`.
	let {
		open = $bindable(false),
		group = [],
		prefill = null,
		onSaved = async () => {},
	}: {
		open: boolean;
		group?: RewriteRule[];
		prefill?: { domain: string; answer: string } | null;
		onSaved?: () => Promise<void>;
	} = $props();

	type DeviceRecords = "DEVICE" | "A" | "AAAA";
	const DEVICE_RECORDS: { value: DeviceRecords; label: string }[] = [
		{ value: "DEVICE", label: "IPv4 and IPv6" },
		{ value: "A", label: "IPv4 only" },
		{ value: "AAAA", label: "IPv6 only" },
	];

	let mode = $state<"static" | "device">("static");
	let domain = $state("");
	let saving = $state(false);

	// Mode 1: Static Target
	let staticAnswer = $state("");

	// Mode 2: Dynamic Device Target (dev:)
	let knownDevices = $state<DeviceEntry[]>([]);
	let selectedDeviceIdentifier = $state("");
	let deviceRecords = $state<DeviceRecords>("DEVICE");
	let fallbackV4 = $state("");
	let fallbackV6 = $state("");

	const editing = $derived(group.length > 0);
	const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

	// A static answer gives its own type: an IPv4 address, an IPv6 address or a host name.
	function staticType(answer: string): DnsRecordType {
		if (answer.includes(":")) return "AAAA";
		return IPV4.test(answer) ? "A" : "CNAME";
	}
	const staticRtype = $derived(staticType(staticAnswer.trim()));

	async function fetchDevices() {
		try {
			const res = await listDevices();
			if (res && res.devices) {
				knownDevices = res.devices;
			}
		} catch {
			// silent fallback
		}
	}

	$effect(() => {
		if (!open) return;
		fetchDevices();
		const first = group[0];
		domain = first?.domain ?? prefill?.domain ?? "";
		staticAnswer = "";
		selectedDeviceIdentifier = "";
		deviceRecords = "DEVICE";
		fallbackV4 = "";
		fallbackV6 = "";
		const dev = first ? splitDeviceAnswer(first.answer) : null;
		if (first && dev) {
			mode = "device";
			selectedDeviceIdentifier = dev.device;
			deviceRecords = first.rtype === "A" || first.rtype === "AAAA" ? first.rtype : "DEVICE";
			for (const r of group) {
				const fb = splitDeviceAnswer(r.answer)?.fallback ?? "";
				if (fb.includes(":")) fallbackV6 = fb;
				else if (fb) fallbackV4 = fb;
			}
		} else {
			mode = "static";
			staticAnswer = first ? formatRewriteAnswer(first.answer) : (prefill?.answer ?? "");
		}
	});

	// The rules the form stands for: a device gets one rule per fallback.
	function wantedRules(dom: string): { domain: string; rtype: DnsRecordType; answer: string }[] {
		if (mode === "static") {
			const answer = staticAnswer.trim();
			if (!answer) throw new Error("Please specify an IP address or CNAME target domain");
			return [{ domain: dom, rtype: staticType(answer), answer }];
		}
		const device = selectedDeviceIdentifier.trim();
		if (!device) throw new Error("Please select or enter a device identifier");
		const fallbacks = [
			deviceRecords !== "AAAA" ? fallbackV4.trim() : "",
			deviceRecords !== "A" ? fallbackV6.trim() : "",
		].filter(Boolean);
		const answers = fallbacks.length
			? fallbacks.map((fb) => `dev:${device}|${fb}`)
			: [`dev:${device}`];
		return answers.map((answer) => ({ domain: dom, rtype: deviceRecords, answer }));
	}

	const sameRule = (a: RewriteRule, b: { domain: string; rtype: DnsRecordType; answer: string }) =>
		a.domain.toLowerCase() === b.domain.toLowerCase() &&
		a.rtype === b.rtype &&
		formatRewriteAnswer(a.answer) === b.answer;

	async function handleSubmit() {
		const dom = domain.trim().replace(/\.$/, "");
		if (!dom) {
			toast.error("Please specify a domain pattern");
			return;
		}

		try {
			const wanted = wantedRules(dom);
			saving = true;
			for (const rule of wanted) {
				await dnsRewriteAdd(rule);
			}
			// Edited rules the new ones did not replace go away.
			const stale = group.filter((old) => !wanted.some((w) => sameRule(old, w)));
			if (stale.length) {
				const live = await dnsRewriteList();
				for (const old of stale) {
					const kept = live.find((r) =>
						sameRule(r, { domain: old.domain, rtype: old.rtype, answer: formatRewriteAnswer(old.answer) }),
					);
					if (kept) await dnsRewriteRemove(kept);
				}
			}
			toast.success(editing ? "Updated DNS rewrite rule" : "Added DNS rewrite rule");
			open = false;
			await onSaved();
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
				{editing ? "Edit DNS Rewrite Rule" : "Add DNS Rewrite Rule"}
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
				<Tabs.List class="grid grid-cols-2 w-full h-9">
					<Tabs.Trigger value="static" class="text-xs gap-1">
						<GlobeIcon class="h-3.5 w-3.5" />
						Static Target
					</Tabs.Trigger>
					<Tabs.Trigger value="device" class="text-xs gap-1">
						<LaptopIcon class="h-3.5 w-3.5" />
						Device (dev:)
					</Tabs.Trigger>
				</Tabs.List>

				<!-- Mode 1: Static Target -->
				<Tabs.Content value="static" class="space-y-1.5 pt-3">
					<Label for="static-target" class="text-xs font-medium"
						>IP Address / CNAME Target</Label
					>
					<Input
						id="static-target"
						type="text"
						placeholder="192.168.1.50, fd00::50, or alias.lan"
						class="h-9 text-xs font-mono"
						bind:value={staticAnswer}
					/>
					<p class="text-[11px] text-muted-foreground">
						Answers <code class="font-mono text-primary font-semibold">{staticRtype}</code> queries
						(the type follows the target).
					</p>
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
						<Label class="text-xs font-medium">Answers</Label>
						<Select.Root
							type="single"
							value={deviceRecords}
							onValueChange={(val) => (deviceRecords = (val as DeviceRecords) ?? "DEVICE")}
						>
							<Select.Trigger class="h-9 text-xs">
								{DEVICE_RECORDS.find((r) => r.value === deviceRecords)?.label}
							</Select.Trigger>
							<Select.Content>
								{#each DEVICE_RECORDS as r (r.value)}
									<Select.Item value={r.value} class="text-xs">{r.label}</Select.Item>
								{/each}
							</Select.Content>
						</Select.Root>
					</div>

					<div class="grid grid-cols-2 gap-2">
						{#if deviceRecords !== "AAAA"}
							<div class="space-y-1.5">
								<Label for="device-fallback-v4" class="text-xs font-medium"
									>IPv4 Fallback</Label
								>
								<Input
									id="device-fallback-v4"
									type="text"
									placeholder="e.g. 192.168.1.100"
									class="h-9 text-xs font-mono"
									bind:value={fallbackV4}
								/>
							</div>
						{/if}
						{#if deviceRecords !== "A"}
							<div class="space-y-1.5">
								<Label for="device-fallback-v6" class="text-xs font-medium"
									>IPv6 Fallback</Label
								>
								<Input
									id="device-fallback-v6"
									type="text"
									placeholder="e.g. fd00::100"
									class="h-9 text-xs font-mono"
									bind:value={fallbackV6}
								/>
							</div>
						{/if}
					</div>

					<p class="text-[11px] text-muted-foreground">
						Answers with the device's live addresses; a fallback (optional) is used while
						the device has no address of that family.
					</p>
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
					{editing ? "Update Rule" : "Create Rewrite Rule"}
				{/if}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
