<script lang="ts">
  import * as Dialog from "$lib/components/ui/dialog";
  import * as Card from "$lib/components/ui/card";
  import { Button } from "$lib/components/ui/button";
  import { Input } from "$lib/components/ui/input";
  import { Badge } from "$lib/components/ui/badge";
  import { cn } from "$lib/utils";
  import ShieldIcon from "@lucide/svelte/icons/shield";
  import WifiIcon from "@lucide/svelte/icons/wifi";
  import UsersIcon from "@lucide/svelte/icons/users";
  import ServerIcon from "@lucide/svelte/icons/server";
  import type { FirewallZone, FirewallPolicy } from "$lib/api/types";

  interface Props {
    open: boolean;
    onAdd: (zone: FirewallZone) => void;
    onClose: () => void;
  }

  let { open = $bindable(), onAdd, onClose }: Props = $props();

  // ── Template definitions ───────────────────────────────────────────────
  interface ZoneTemplate {
    id: string;
    label: string;
    description: string;
    Icon: typeof ShieldIcon;
    input_policy: FirewallPolicy;
    forward_policy: FirewallPolicy;
    masquerade: boolean;
    mtu_fix: boolean;
  }

  const TEMPLATES: ZoneTemplate[] = [
    {
      id: "lan",
      label: "LAN / Interna",
      description: "Rede local confiável, tráfego livre",
      Icon: ShieldIcon,
      input_policy: "Accept",
      forward_policy: "Accept",
      masquerade: false,
      mtu_fix: false,
    },
    {
      id: "guest",
      label: "Guest / Convidado",
      description: "Sem acesso à rede interna",
      Icon: UsersIcon,
      input_policy: "Drop",
      forward_policy: "Drop",
      masquerade: false,
      mtu_fix: false,
    },
    {
      id: "iot",
      label: "IoT",
      description: "Isolada, sem saída pra internal",
      Icon: WifiIcon,
      input_policy: "Drop",
      forward_policy: "Drop",
      masquerade: false,
      mtu_fix: false,
    },
    {
      id: "dmz",
      label: "DMZ",
      description: "Aceita entrada, sem acesso interno",
      Icon: ServerIcon,
      input_policy: "Accept",
      forward_policy: "Drop",
      masquerade: false,
      mtu_fix: true,
    },
  ];

  // ── Form state ─────────────────────────────────────────────────────────
  let formName = $state("");
  let selectedTemplateId = $state<string>("lan");
  let nameError = $state<string | null>(null);

  const selectedTemplate = $derived(
    TEMPLATES.find((t) => t.id === selectedTemplateId) ?? TEMPLATES[0]
  );

  // ── Validation ─────────────────────────────────────────────────────────
  function validate(): boolean {
    const trimmed = formName.trim();
    if (!trimmed) {
      nameError = "O nome da zona é obrigatório.";
      return false;
    }
    if (/\s/.test(trimmed)) {
      nameError = "O nome não pode conter espaços.";
      return false;
    }
    nameError = null;
    return true;
  }

  // ── Submit ─────────────────────────────────────────────────────────────
  function handleAdd() {
    if (!validate()) return;

    const tpl = selectedTemplate;
    const newZone: FirewallZone = {
      name: formName.trim().toLowerCase(),
      interfaces: [],
      open_ports: [],
      allowed_subnets: [],
      input_policy: tpl.input_policy,
      forward_policy: tpl.forward_policy,
      masquerade: tpl.masquerade,
      mtu_fix: tpl.mtu_fix,
    };

    onAdd(newZone);
    resetForm();
  }

  function handleClose() {
    resetForm();
    onClose();
  }

  function resetForm() {
    formName = "";
    selectedTemplateId = "lan";
    nameError = null;
  }

  function handleNameInput() {
    // Clear error as user types
    if (nameError) nameError = null;
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === "Enter") handleAdd();
  }
</script>

<Dialog.Root bind:open onOpenChange={(o) => { if (!o) handleClose(); }}>
  <Dialog.Content class="sm:max-w-lg">
    <Dialog.Header>
      <Dialog.Title>Nova zona de firewall</Dialog.Title>
      <Dialog.Description>
        Escolha um template e dê um nome único à zona.
      </Dialog.Description>
    </Dialog.Header>

    <div class="flex flex-col gap-5 py-2">

      <!-- Zone name input -->
      <div class="flex flex-col gap-1.5">
        <label for="zone-name" class="text-sm font-medium">
          Nome da zona
          <span class="text-destructive ml-0.5">*</span>
        </label>
        <Input
          id="zone-name"
          placeholder="ex: dmz, iot, guest"
          bind:value={formName}
          oninput={handleNameInput}
          onkeydown={handleKeydown}
          autocomplete="off"
          class={cn(nameError && "border-destructive focus-visible:ring-destructive")}
        />
        {#if nameError}
          <p class="text-destructive text-xs">{nameError}</p>
        {/if}
      </div>

      <!-- Template picker 2×2 grid -->
      <div class="flex flex-col gap-1.5">
        <span class="text-sm font-medium">Template</span>
        <div class="grid grid-cols-2 gap-2">
          {#each TEMPLATES as tpl (tpl.id)}
            {@const isSelected = selectedTemplateId === tpl.id}
            <button
              type="button"
              onclick={() => (selectedTemplateId = tpl.id)}
              class={cn(
                "rounded-lg border p-3 text-left transition-all duration-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                isSelected
                  ? "ring-2 ring-primary border-primary bg-primary/5"
                  : "border-border hover:border-muted-foreground/40 hover:bg-muted/40"
              )}
            >
              <div class="flex items-start gap-2">
                <tpl.Icon
                  class={cn(
                    "mt-0.5 size-4 shrink-0",
                    isSelected ? "text-primary" : "text-muted-foreground"
                  )}
                />
                <div class="flex flex-col gap-0.5">
                  <span class="text-sm font-semibold leading-none">{tpl.label}</span>
                  <span class="text-muted-foreground text-xs leading-snug">{tpl.description}</span>
                </div>
              </div>

              <!-- Policy badges -->
              <div class="mt-2 flex flex-wrap gap-1">
                <Badge
                  variant={tpl.input_policy === "Accept" ? "default" : "secondary"}
                  class="text-[10px]"
                >
                  in: {tpl.input_policy}
                </Badge>
                <Badge
                  variant={tpl.forward_policy === "Accept" ? "default" : "secondary"}
                  class="text-[10px]"
                >
                  fwd: {tpl.forward_policy}
                </Badge>
                {#if tpl.mtu_fix}
                  <Badge variant="outline" class="text-[10px]">MTU fix</Badge>
                {/if}
              </div>
            </button>
          {/each}
        </div>
      </div>

    </div>

    <Dialog.Footer class="flex gap-2 pt-2">
      <Button variant="outline" onclick={handleClose}>Cancelar</Button>
      <Button onclick={handleAdd} disabled={!formName.trim()}>Adicionar</Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
