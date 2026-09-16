<script lang="ts">
  import * as Card from "$lib/components/ui/card";
  import * as Tooltip from "$lib/components/ui/tooltip";
  import * as ToggleGroup from "$lib/components/ui/toggle-group";
  import { Badge } from "$lib/components/ui/badge";
  import { Button } from "$lib/components/ui/button";
  import { Switch } from "$lib/components/ui/switch";
  import { Input } from "$lib/components/ui/input";
  import { Separator } from "$lib/components/ui/separator";
  import InfoPopover from "$lib/components/InfoPopover.svelte";
  import { cn } from "$lib/utils";
  import TrashIcon from "@lucide/svelte/icons/trash-2";
  import PlusIcon from "@lucide/svelte/icons/plus";
  import XIcon from "@lucide/svelte/icons/x";
  import GlobeIcon from "@lucide/svelte/icons/globe";
  import type { FirewallZone, FirewallPolicy, NetworkInterfaceInfo } from "$lib/api/types";

  interface Props {
    zone: FirewallZone;
    highlighted: boolean;
    availableInterfaces?: NetworkInterfaceInfo[];
    activeWan?: string | null;
    onUpdate: (updated: FirewallZone) => void;
    onDelete: () => void;
  }

  let {
    zone,
    highlighted,
    availableInterfaces = [],
    activeWan = null,
    onUpdate,
    onDelete,
  }: Props = $props();

  // ── Inline "add interface" state ──────────────────────────────────────────
  let addingInterface = $state(false);
  let customInterfaceMode = $state(false);
  let selectedIfaceToAdd = $state("");
  let newInterfaceValue = $state("");

  // Filter available interfaces not yet in this zone
  const unassignedInterfaces = $derived(
    availableInterfaces.filter((i) => !zone.interfaces.includes(i.name))
  );

  // Check if this is an external zone missing its active WAN
  const isExternalZone = $derived(
    zone.name.toLowerCase() === "external" || zone.name.toLowerCase() === "wan"
  );
  const activeWanMissing = $derived(
    isExternalZone && activeWan && !zone.interfaces.includes(activeWan)
  );

  // ── Zone-name → accent dot colour ────────────────────────────────────────
  const DOT_COLOURS: Record<string, string> = {
    internal: "bg-emerald-500",
    external: "bg-destructive",
    trusted: "bg-primary",
    guest: "bg-amber-500",
    iot: "bg-purple-500",
  };

  const dotColour = $derived(DOT_COLOURS[zone.name.toLowerCase()] ?? "bg-muted-foreground");

  // ── Helpers that produce updated zone objects and call onUpdate ───────────
  function addSelectedInterface() {
    const chosen = selectedIfaceToAdd.trim();
    if (!chosen) return;
    if (!zone.interfaces.includes(chosen)) {
      onUpdate({ ...zone, interfaces: [...zone.interfaces, chosen] });
    }
    selectedIfaceToAdd = "";
    addingInterface = false;
    customInterfaceMode = false;
  }

  function addCustomInterface() {
    const trimmed = newInterfaceValue.trim();
    if (!trimmed) return;
    if (!zone.interfaces.includes(trimmed)) {
      onUpdate({ ...zone, interfaces: [...zone.interfaces, trimmed] });
    }
    newInterfaceValue = "";
    addingInterface = false;
    customInterfaceMode = false;
  }

  function bindActiveWan() {
    if (!activeWan || zone.interfaces.includes(activeWan)) return;
    onUpdate({ ...zone, interfaces: [...zone.interfaces, activeWan] });
  }

  function removeInterface(iface: string) {
    onUpdate({ ...zone, interfaces: zone.interfaces.filter((i) => i !== iface) });
  }

  function setInputPolicy(value: string | undefined) {
    if (!value) return;
    onUpdate({ ...zone, input_policy: value as FirewallPolicy });
  }

  function setForwardPolicy(value: string | undefined) {
    if (!value) return;
    onUpdate({ ...zone, forward_policy: value as FirewallPolicy });
  }

  function setMasquerade(checked: boolean) {
    onUpdate({ ...zone, masquerade: checked });
  }

  function setMtuFix(checked: boolean) {
    onUpdate({ ...zone, mtu_fix: checked });
  }
</script>

<Card.Root
  class={cn(
    "transition-shadow duration-150",
    highlighted && "ring-2 ring-primary/40"
  )}
>
  <!-- ── Header ─────────────────────────────────────────────────────────── -->
  <Card.Header class="flex flex-row items-center justify-between pb-2">
    <div class="flex items-center gap-2">
      <span class={cn("size-2.5 shrink-0 rounded-full", dotColour)}></span>
      <Card.Title class="text-base font-bold leading-none">{zone.name}</Card.Title>
    </div>

    <Tooltip.Provider>
      <Tooltip.Root>
        <Tooltip.Trigger>
          {#snippet child({ props })}
            <Button
              {...props}
              variant="ghost"
              size="icon"
              class="text-muted-foreground hover:text-destructive hover:bg-destructive/10 size-8 shrink-0"
              onclick={onDelete}
              aria-label="Delete zone"
            >
              <TrashIcon data-icon="inline-start" />
            </Button>
          {/snippet}
        </Tooltip.Trigger>
        <Tooltip.Content>Delete zone</Tooltip.Content>
      </Tooltip.Root>
    </Tooltip.Provider>
  </Card.Header>

  <!-- ── Content ────────────────────────────────────────────────────────── -->
  <Card.Content class="flex flex-col gap-4 pt-0">

    <!-- Interfaces -->
    <div class="flex flex-col gap-1.5">
      <div class="flex items-center justify-between">
        <span class="text-muted-foreground text-xs font-medium uppercase tracking-wide">
          Interfaces
        </span>
        {#if activeWanMissing}
          <button
            type="button"
            class="flex items-center gap-1 text-[11px] text-destructive hover:underline cursor-pointer"
            onclick={bindActiveWan}
          >
            <GlobeIcon class="size-3" />
            Attach WAN ({activeWan})
          </button>
        {/if}
      </div>

      <div class="flex flex-wrap items-center gap-1.5">
        {#if zone.interfaces.length === 0 && !addingInterface}
          <span class="text-xs text-muted-foreground italic">No interfaces attached</span>
        {/if}

        {#each zone.interfaces as iface (iface)}
          <Badge variant="secondary" class="flex items-center gap-1 pr-1">
            {iface}
            <button
              type="button"
              class="rounded-full p-0.5 hover:bg-muted focus-visible:outline-none focus-visible:ring-1 cursor-pointer"
              onclick={() => removeInterface(iface)}
              aria-label="Remove {iface}"
            >
              <XIcon class="size-3" />
            </button>
          </Badge>
        {/each}

        {#if !addingInterface}
          <Button
            variant="outline"
            size="icon"
            class="size-6"
            aria-label="Add interface"
            onclick={() => {
              addingInterface = true;
              selectedIfaceToAdd = unassignedInterfaces[0]?.name ?? "";
            }}
          >
            <PlusIcon data-icon="inline-start" />
          </Button>
        {/if}
      </div>

      {#if addingInterface}
        <div class="flex flex-col gap-2 p-2.5 rounded-lg border border-border/70 bg-muted/30 w-full mt-1">
          <div class="flex items-center justify-between">
            <span class="text-[11px] font-semibold text-foreground">Attach Interface</span>
            <button
              type="button"
              class="text-muted-foreground hover:text-foreground text-xs cursor-pointer"
              onclick={() => { addingInterface = false; customInterfaceMode = false; }}
              aria-label="Cancel"
            >
              <XIcon class="size-3.5" />
            </button>
          </div>

          {#if !customInterfaceMode && unassignedInterfaces.length > 0}
            <div class="flex items-center gap-1.5">
              <select
                class="flex h-8 w-full rounded-md border border-input bg-background px-2.5 py-1 text-xs"
                bind:value={selectedIfaceToAdd}
              >
                <option value="" disabled>Select interface…</option>
                {#each unassignedInterfaces as iface}
                  <option value={iface.name}>
                    {iface.name} ({iface.bus_type} - {iface.carrier_up ? '🟢 Connected' : '⚪ Disconnected'} {iface.ips[0] ? `[${iface.ips[0]}]` : ''})
                  </option>
                {/each}
              </select>
              <Button
                size="sm"
                class="h-8 text-xs px-2.5 shrink-0"
                disabled={!selectedIfaceToAdd}
                onclick={addSelectedInterface}
              >
                Add
              </Button>
            </div>
            <button
              type="button"
              class="text-[11px] text-primary hover:underline text-left cursor-pointer"
              onclick={() => { customInterfaceMode = true; }}
            >
              Or type custom / virtual interface name…
            </button>
          {:else}
            <div class="flex items-center gap-1.5">
              <Input
                class="h-8 px-2.5 py-1 text-xs"
                placeholder="e.g. wg0, podman*, eth1"
                bind:value={newInterfaceValue}
                onkeydown={(e) => {
                  if (e.key === "Enter") addCustomInterface();
                  if (e.key === "Escape") { addingInterface = false; customInterfaceMode = false; }
                }}
                autofocus
              />
              <Button
                size="sm"
                class="h-8 text-xs px-2.5 shrink-0"
                disabled={!newInterfaceValue.trim()}
                onclick={addCustomInterface}
              >
                Add
              </Button>
            </div>
            {#if unassignedInterfaces.length > 0}
              <button
                type="button"
                class="text-[11px] text-primary hover:underline text-left cursor-pointer"
                onclick={() => { customInterfaceMode = false; }}
              >
                ← Back to detected interface list
              </button>
            {/if}
          {/if}
        </div>
      {/if}
    </div>

    <Separator />

    <!-- Input Policy -->
    <div class="flex flex-col gap-1.5">
      <span class="text-muted-foreground text-xs font-medium uppercase tracking-wide">
        Input Policy
      </span>
      <ToggleGroup.Root
        type="single"
        variant="outline"
        size="sm"
        value={zone.input_policy}
        onValueChange={setInputPolicy}
      >
        <ToggleGroup.Item value="Accept">Accept</ToggleGroup.Item>
        <ToggleGroup.Item value="Drop">Drop</ToggleGroup.Item>
        <ToggleGroup.Item value="Reject">Reject</ToggleGroup.Item>
      </ToggleGroup.Root>
    </div>

    <!-- Forward Policy -->
    <div class="flex flex-col gap-1.5">
      <span class="text-muted-foreground text-xs font-medium uppercase tracking-wide">
        Forward Policy
      </span>
      <ToggleGroup.Root
        type="single"
        variant="outline"
        size="sm"
        value={zone.forward_policy}
        onValueChange={setForwardPolicy}
      >
        <ToggleGroup.Item value="Accept">Accept</ToggleGroup.Item>
        <ToggleGroup.Item value="Drop">Drop</ToggleGroup.Item>
        <ToggleGroup.Item value="Reject">Reject</ToggleGroup.Item>
      </ToggleGroup.Root>
    </div>

    <Separator />

    <!-- Masquerade -->
    <div class="flex items-start justify-between gap-3">
      <div class="flex flex-col gap-0.5">
        <div class="flex items-center gap-1.5">
          <span class="text-sm font-medium leading-none">Masquerade</span>
          <InfoPopover
            title="Outbound NAT (Masquerade)"
            description="Rewrites source IP to this router's external public IP when traffic leaves this zone. Essential for WAN uplink interfaces."
          />
        </div>
        <span class="text-muted-foreground text-xs">
          Enable outbound NAT (SNAT)
        </span>
      </div>
      <Switch
        checked={zone.masquerade}
        onCheckedChange={setMasquerade}
        aria-label="Masquerade"
      />
    </div>

    <!-- MSS Clamping -->
    <div class="flex items-start justify-between gap-3">
      <div class="flex flex-col gap-0.5">
        <div class="flex items-center gap-1.5">
          <span class="text-sm font-medium leading-none">MSS Clamping</span>
          <InfoPopover
            title="TCP MSS Clamping"
            description="Limits TCP Maximum Segment Size to avoid MTU fragmentation on PPPoE (1452 bytes) and tunnel connections."
          />
        </div>
        <span class="text-muted-foreground text-xs">
          Fix TCP MSS for PPPoE / WAN links
        </span>
      </div>
      <Switch
        checked={zone.mtu_fix}
        onCheckedChange={setMtuFix}
        aria-label="MSS Clamping"
      />
    </div>

  </Card.Content>
</Card.Root>
