<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Table from "$lib/components/ui/table";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";

	let {
		v4RawOptions = $bindable<Array<{ code: number; value: string }>>([]),
		v6RawOptions = $bindable<Array<{ code: number; value: string }>>([]),
	}: {
		v4RawOptions?: Array<{ code: number; value: string }>;
		v6RawOptions?: Array<{ code: number; value: string }>;
	} = $props();

	let newRawV4Code = $state<number | "">("");
	let newRawV4Value = $state("");
	let newRawV6Code = $state<number | "">("");
	let newRawV6Value = $state("");

	function addV4() {
		if (typeof newRawV4Code === "number" && newRawV4Code > 0 && newRawV4Value.trim()) {
			v4RawOptions = [
				...v4RawOptions.filter((o) => o.code !== newRawV4Code),
				{ code: newRawV4Code, value: newRawV4Value.trim() },
			];
			newRawV4Code = "";
			newRawV4Value = "";
		}
	}

	function removeV4(idx: number) {
		v4RawOptions = v4RawOptions.filter((_, i) => i !== idx);
	}

	function addV6() {
		if (typeof newRawV6Code === "number" && newRawV6Code > 0 && newRawV6Value.trim()) {
			v6RawOptions = [
				...v6RawOptions.filter((o) => o.code !== newRawV6Code),
				{ code: newRawV6Code, value: newRawV6Value.trim() },
			];
			newRawV6Code = "";
			newRawV6Value = "";
		}
	}

	function removeV6(idx: number) {
		v6RawOptions = v6RawOptions.filter((_, i) => i !== idx);
	}
</script>

<Card.Root class="border-border/80 shadow-sm overflow-hidden">
	<Card.Header class="bg-muted/20 border-b pb-4">
		<div class="flex items-center gap-2.5">
			<SlidersIcon class="size-5 text-emerald-500" />
			<div>
				<Card.Title class="text-base font-bold">Custom Raw DHCP Options</Card.Title>
				<Card.Description class="text-xs">
					Inject arbitrary RFC or vendor-specific option code payloads into DHCP packets
				</Card.Description>
			</div>
		</div>
	</Card.Header>

	<Card.Content class="p-4 sm:p-6">
		<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
			<!-- IPv4 Raw Options -->
			<div class="flex flex-col gap-3">
				<div class="flex items-center gap-2">
					<Badge variant="outline" class="font-mono text-[10px] text-blue-500 border-blue-500/30">
						IPv4
					</Badge>
					<span class="text-xs font-bold text-foreground">Raw Option Codes</span>
				</div>

				{#if v4RawOptions.length > 0}
					<div class="border rounded-lg overflow-hidden font-mono text-xs">
						<Table.Root>
							<Table.Header class="bg-muted/40">
								<Table.Row>
									<Table.Head class="w-28">Option Code</Table.Head>
									<Table.Head>Payload</Table.Head>
									<Table.Head class="w-12 text-right"></Table.Head>
								</Table.Row>
							</Table.Header>
							<Table.Body>
								{#each v4RawOptions as opt, idx}
									<Table.Row>
										<Table.Cell class="font-bold">Option {opt.code}</Table.Cell>
										<Table.Cell>{opt.value}</Table.Cell>
										<Table.Cell class="text-right">
											<Button
												variant="ghost"
												size="icon"
												class="size-6 text-destructive hover:text-destructive"
												onclick={() => removeV4(idx)}
											>
												<Trash2Icon class="size-3.5" />
											</Button>
										</Table.Cell>
									</Table.Row>
								{/each}
							</Table.Body>
						</Table.Root>
					</div>
				{/if}

				<div class="flex items-center gap-2">
					<Input
						type="number"
						placeholder="Code (e.g. 43)"
						class="w-32 font-mono text-xs"
						bind:value={newRawV4Code}
					/>
					<Input
						placeholder="Option payload / string..."
						class="flex-1 font-mono text-xs"
						bind:value={newRawV4Value}
						onkeydown={(e) => e.key === "Enter" && addV4()}
					/>
					<Button size="sm" variant="outline" onclick={addV4} class="h-9 text-xs">
						<PlusIcon class="size-3.5 mr-1" />
						Add
					</Button>
				</div>
			</div>

			<!-- IPv6 Raw Options -->
			<div class="flex flex-col gap-3">
				<div class="flex items-center gap-2">
					<Badge variant="outline" class="font-mono text-[10px] text-purple-500 border-purple-500/30">
						IPv6
					</Badge>
					<span class="text-xs font-bold text-foreground">Raw Option Codes</span>
				</div>

				{#if v6RawOptions.length > 0}
					<div class="border rounded-lg overflow-hidden font-mono text-xs">
						<Table.Root>
							<Table.Header class="bg-muted/40">
								<Table.Row>
									<Table.Head class="w-28">Option Code</Table.Head>
									<Table.Head>Payload</Table.Head>
									<Table.Head class="w-12 text-right"></Table.Head>
								</Table.Row>
							</Table.Header>
							<Table.Body>
								{#each v6RawOptions as opt, idx}
									<Table.Row>
										<Table.Cell class="font-bold">Option {opt.code}</Table.Cell>
										<Table.Cell>{opt.value}</Table.Cell>
										<Table.Cell class="text-right">
											<Button
												variant="ghost"
												size="icon"
												class="size-6 text-destructive hover:text-destructive"
												onclick={() => removeV6(idx)}
											>
												<Trash2Icon class="size-3.5" />
											</Button>
										</Table.Cell>
									</Table.Row>
								{/each}
							</Table.Body>
						</Table.Root>
					</div>
				{/if}

				<div class="flex items-center gap-2">
					<Input
						type="number"
						placeholder="Code (e.g. 56)"
						class="w-32 font-mono text-xs"
						bind:value={newRawV6Code}
					/>
					<Input
						placeholder="Option payload / string..."
						class="flex-1 font-mono text-xs"
						bind:value={newRawV6Value}
						onkeydown={(e) => e.key === "Enter" && addV6()}
					/>
					<Button size="sm" variant="outline" onclick={addV6} class="h-9 text-xs">
						<PlusIcon class="size-3.5 mr-1" />
						Add
					</Button>
				</div>
			</div>
		</div>
	</Card.Content>
</Card.Root>
