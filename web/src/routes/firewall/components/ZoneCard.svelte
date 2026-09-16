<script lang="ts">
  import * as Card from "$lib/components/ui/card";
  import * as Tooltip from "$lib/components/ui/tooltip";
  import * as ToggleGroup from "$lib/components/ui/toggle-group";
  import { Badge } from "$lib/components/ui/badge";
  import { Button } from "$lib/components/ui/button";
  import { Switch } from "$lib/components/ui/switch";
  import { Input } from "$lib/components/ui/input";
  import { Separator } from "$lib/components/ui/separator";
  import { cn } from "$lib/utils";
  import TrashIcon from "@lucide/svelte/icons/trash-2";
  import PlusIcon from "@lucide/svelte/icons/plus";
  import XIcon from "@lucide/svelte/icons/x";
  import type { FirewallZone, FirewallPolicy } from "$lib/api/types";

  interface Props {
    zone: FirewallZone;
    highlighted: boolean;
    onUpdate: (updated: FirewallZone) => void;
    onDelete: () => void;
  }

  let { zone, highlighted, onUpdate, onDelete }: Props = $props();

  // ── Inline "add interface" state ──────────────────────────────────────────
  let addingInterface = $state(false);
  let newInterfaceValue = $state("");

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
  function addInterface() {
    const trimmed = newInterfaceValue.trim();
    if (!trimmed) return;
    onUpdate({ ...zone, interfaces: [...zone.interfaces, trimmed] });
    newInterfaceValue = "";
    addingInterface = false;
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

  function handleNewInterfaceKeydown(e: KeyboardEvent) {
    if (e.key === "Enter") addInterface();
    if (e.key === "Escape") {
      addingInterface = false;
      newInterfaceValue = "";
    }
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
      <span class="text-muted-foreground text-xs font-medium uppercase tracking-wide">
        Interfaces
      </span>
      <div class="flex flex-wrap items-center gap-1.5">
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

        {#if addingInterface}
          <Input
            class="h-6 w-28 px-2 py-0 text-xs"
            placeholder="eth0"
            bind:value={newInterfaceValue}
            onkeydown={handleNewInterfaceKeydown}
            onblur={addInterface}
            autofocus
          />
        {:else}
          <Button
            variant="outline"
            size="icon"
            class="size-6"
            aria-label="Add interface"
            onclick={() => (addingInterface = true)}
          >
            <PlusIcon data-icon="inline-start" />
          </Button>
        {/if}
      </div>
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
        <span class="text-sm font-medium leading-none">Masquerade</span>
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
        <span class="text-sm font-medium leading-none">MSS Clamping</span>
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
