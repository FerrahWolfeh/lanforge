<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Input } from "$lib/components/ui/input";
	import { Label } from "$lib/components/ui/label";
	import { Switch } from "$lib/components/ui/switch";
	import SlidersIcon from "@lucide/svelte/icons/sliders";

	let {
		formMru = $bindable(1492),
		formEchoInterval = $bindable(20),
		formEchoMaxFailures = $bindable(5),
		formReconnectDelay = $bindable(10),
		formSendPadt = $bindable(true),
		formPadiRetries = $bindable(5),
		formPadiTimeout = $bindable(3),
	}: {
		formMru?: number;
		formEchoInterval?: number;
		formEchoMaxFailures?: number;
		formReconnectDelay?: number;
		formSendPadt?: boolean;
		formPadiRetries?: number;
		formPadiTimeout?: number;
	} = $props();
</script>

<div class="flex flex-col gap-6">
	<Card.Root>
		<Card.Header class="pb-3 border-b border-border/50">
			<Card.Title class="text-base font-semibold flex items-center gap-2">
				<SlidersIcon class="size-4 text-primary" />
				Link Parameters & Session Timers
			</Card.Title>
			<Card.Description class="text-xs">
				Control LCP keepalives, discovery retry backoff, and MTU/MRU packet size limits.
			</Card.Description>
		</Card.Header>
		<Card.Content class="p-4 grid gap-4 sm:grid-cols-2">
			<!-- MRU -->
			<div class="flex flex-col gap-1.5">
				<Label for="mru" class="text-xs font-semibold">Maximum Receive Unit (MRU)</Label>
				<Input
					id="mru"
					type="number"
					min="576"
					max="1500"
					bind:value={formMru}
					class="h-9 font-mono text-xs"
				/>
				<p class="text-[11px] text-muted-foreground">
					Default 1492 (1500 Ethernet MTU minus 8-byte PPPoE header). Use 1500 for Baby Jumbo Frames.
				</p>
			</div>

			<!-- Echo Interval -->
			<div class="flex flex-col gap-1.5">
				<Label for="echo_interval" class="text-xs font-semibold">LCP Echo Interval (seconds)</Label>
				<Input
					id="echo_interval"
					type="number"
					min="1"
					max="300"
					bind:value={formEchoInterval}
					class="h-9 font-mono text-xs"
				/>
				<p class="text-[11px] text-muted-foreground">
					Frequency of LCP Echo-Request keepalive probes sent to the BRAS to detect dead links.
				</p>
			</div>

			<!-- Max Echo Failures -->
			<div class="flex flex-col gap-1.5">
				<Label for="echo_failures" class="text-xs font-semibold">Max Echo Failures</Label>
				<Input
					id="echo_failures"
					type="number"
					min="1"
					max="20"
					bind:value={formEchoMaxFailures}
					class="h-9 font-mono text-xs"
				/>
				<p class="text-[11px] text-muted-foreground">
					Number of consecutive missed echo replies before tearing down the session.
				</p>
			</div>

			<!-- Reconnect Delay -->
			<div class="flex flex-col gap-1.5">
				<Label for="reconnect_delay" class="text-xs font-semibold">Reconnect Delay (seconds)</Label>
				<Input
					id="reconnect_delay"
					type="number"
					min="1"
					max="300"
					bind:value={formReconnectDelay}
					class="h-9 font-mono text-xs"
				/>
				<p class="text-[11px] text-muted-foreground">
					Wait period before attempting to re-establish a dropped PPPoE connection.
				</p>
			</div>

			<!-- PADI Retries -->
			<div class="flex flex-col gap-1.5">
				<Label for="padi_retries" class="text-xs font-semibold">PADI Discovery Retries</Label>
				<Input
					id="padi_retries"
					type="number"
					min="1"
					max="30"
					bind:value={formPadiRetries}
					class="h-9 font-mono text-xs"
				/>
				<p class="text-[11px] text-muted-foreground">
					Active PPPoE Active Discovery Initiation attempts before backing off.
				</p>
			</div>

			<!-- PADI Timeout -->
			<div class="flex flex-col gap-1.5">
				<Label for="padi_timeout" class="text-xs font-semibold">PADI Timeout (seconds)</Label>
				<Input
					id="padi_timeout"
					type="number"
					min="1"
					max="60"
					bind:value={formPadiTimeout}
					class="h-9 font-mono text-xs"
				/>
				<p class="text-[11px] text-muted-foreground">
					Wait time for a PADO response packet from upstream BRAS before retransmitting.
				</p>
			</div>

			<!-- PADT on Shutdown -->
			<div class="flex items-start justify-between gap-3 p-3 rounded-lg border bg-muted/20 sm:col-span-2">
				<div class="flex flex-col gap-0.5">
					<Label class="text-xs font-semibold">Send PADT on Shutdown</Label>
					<p class="text-[11px] text-muted-foreground">
						Sends a graceful PPPoE Active Discovery Terminate packet to immediately free the ISP session slot.
					</p>
				</div>
				<Switch bind:checked={formSendPadt} />
			</div>
		</Card.Content>
	</Card.Root>
</div>
