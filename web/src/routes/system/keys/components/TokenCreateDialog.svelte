<script lang="ts">
	import * as Dialog from "$lib/components/ui/dialog";
	import * as Field from "$lib/components/ui/field";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Badge } from "$lib/components/ui/badge";
	import { Switch } from "$lib/components/ui/switch";
	import { Separator } from "$lib/components/ui/separator";
	import KeyRoundIcon from "@lucide/svelte/icons/key-round";
	import SparklesIcon from "@lucide/svelte/icons/sparkles";
	import Loader2Icon from "@lucide/svelte/icons/loader-2";
	import { generateToken } from "$lib/api/client";
	import type { AuthToken, GenerateTokenRequest } from "$lib/api/types";
	import { toast } from "svelte-sonner";

	let {
		open = $bindable(false),
		onCreated
	}: {
		open: boolean;
		onCreated: (token: AuthToken) => void;
	} = $props();

	let formName = $state("");
	let formExpiryPreset = $state<"never" | "7d" | "30d" | "90d" | "1y">("30d");
	let formScopes = $state<Record<string, boolean>>({
		admin: true,
		monitoring: false,
		device_write: false,
		dns_query: false,
		upstream_write: false,
		config_write: false
	});
	let isSubmitting = $state(false);

	const availableScopes = [
		{
			id: "admin",
			label: "Admin",
			desc: "Acesso administrativo irrestrito a todos os serviços, APIs e banco de dados"
		},
		{
			id: "monitoring",
			label: "Monitoring",
			desc: "Apenas leitura de telemetria, status dos serviços e métricas agregadas"
		},
		{
			id: "device_write",
			label: "Device Write",
			desc: "Registro, alteração de propriedades e disparo de pacotes Wake-on-LAN"
		},
		{
			id: "dns_query",
			label: "DNS Query",
			desc: "Execução de consultas de teste no resolvedor e inspeção de logs DNS"
		},
		{
			id: "upstream_write",
			label: "Upstream Write",
			desc: "Configuração e manutenção da lista de provedores DNS upstream"
		},
		{
			id: "config_write",
			label: "Config Write",
			desc: "Importação e aplicação de configurações de pools, leases e roteamento"
		}
	];

	$effect(() => {
		if (open) {
			formName = "";
			formExpiryPreset = "30d";
			formScopes = {
				admin: true,
				monitoring: false,
				device_write: false,
				dns_query: false,
				upstream_write: false,
				config_write: false
			};
		}
	});

	function toggleAdminScope(checked: boolean) {
		formScopes.admin = checked;
		if (checked) {
			formScopes.monitoring = false;
			formScopes.device_write = false;
			formScopes.dns_query = false;
			formScopes.upstream_write = false;
			formScopes.config_write = false;
		}
	}

	function getExpiresAtTimestamp(preset: "never" | "7d" | "30d" | "90d" | "1y"): number | null {
		const now = Math.floor(Date.now() / 1000);
		switch (preset) {
			case "7d":
				return now + 7 * 86400;
			case "30d":
				return now + 30 * 86400;
			case "90d":
				return now + 90 * 86400;
			case "1y":
				return now + 365 * 86400;
			case "never":
			default:
				return null;
		}
	}

	async function handleCreateToken() {
		if (!formName.trim()) {
			toast.error("Informe um nome ou identificador para a chave.");
			return;
		}

		isSubmitting = true;
		try {
			const selectedScopes: string[] = [];
			if (formScopes.admin) {
				selectedScopes.push("admin");
			} else {
				for (const [scope, enabled] of Object.entries(formScopes)) {
					if (enabled) selectedScopes.push(scope);
				}
			}

			if (selectedScopes.length === 0) {
				selectedScopes.push("admin");
			}

			const payload: GenerateTokenRequest = {
				name: formName.trim(),
				scopes: selectedScopes,
				expires_at: getExpiresAtTimestamp(formExpiryPreset)
			};

			const created = await generateToken(payload);
			toast.success(`Chave '${created.name}' gerada com sucesso!`);
			open = false;
			onCreated(created);
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : "Erro ao gerar chave de API.";
			toast.error(msg);
		} finally {
			isSubmitting = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="sm:max-w-lg rounded-2xl">
		<Dialog.Header>
			<Dialog.Title class="text-base font-bold flex items-center gap-2">
				<KeyRoundIcon class="size-5 text-primary" />
				Nova Chave de API
			</Dialog.Title>
			<Dialog.Description class="text-xs">
				Gere uma chave de autenticação para seu aplicativo ou serviço. O segredo será exibido somente uma vez.
			</Dialog.Description>
		</Dialog.Header>

		<form
			onsubmit={(e) => {
				e.preventDefault();
				handleCreateToken();
			}}
			class="flex flex-col gap-4 py-2"
		>
			<Field.FieldGroup class="flex flex-col gap-3">
				<!-- Nome -->
				<Field.Field>
					<Field.FieldLabel for="token-name" class="text-xs font-semibold">
						Nome / Identificador *
					</Field.FieldLabel>
					<Input
						id="token-name"
						placeholder="Ex: Home Assistant, Prometheus, Backup Script"
						bind:value={formName}
						class="text-xs rounded-xl h-9 bg-background"
					/>
					<Field.FieldDescription class="text-[11px] text-muted-foreground">
						Um rótulo descritivo para reconhecer onde esta chave está configurada.
					</Field.FieldDescription>
				</Field.Field>

				<!-- Validade -->
				<Field.Field>
					<Field.FieldLabel for="token-expiry" class="text-xs font-semibold">
						Tempo de Validade
					</Field.FieldLabel>
					<select
						id="token-expiry"
						bind:value={formExpiryPreset}
						class="w-full h-9 text-xs rounded-xl bg-background border border-input px-3 text-foreground outline-none focus-visible:ring-1 focus-visible:ring-ring"
					>
						<option value="7d">7 dias</option>
						<option value="30d">30 dias (Recomendado)</option>
						<option value="90d">90 dias</option>
						<option value="1y">1 ano</option>
						<option value="never">Nunca expira (Uso permanente)</option>
					</select>
				</Field.Field>

				<!-- Escopos -->
				<Field.FieldSet class="flex flex-col gap-2 pt-1">
					<Field.FieldLegend class="text-xs font-semibold">
						Permissões & Escopos
					</Field.FieldLegend>
					<div class="flex flex-col gap-2 rounded-xl border border-border/60 p-3 bg-muted/20">
						{#each availableScopes as sc}
							<div class="flex items-start justify-between gap-3 py-1">
								<div class="flex flex-col gap-0.5">
									<span class="text-xs font-semibold text-foreground flex items-center gap-1.5">
										{sc.label}
										{#if sc.id === 'admin'}
											<Badge variant="default" class="text-[9px] px-1 py-0">Recomendado</Badge>
										{/if}
									</span>
									<span class="text-[11px] text-muted-foreground leading-tight">
										{sc.desc}
									</span>
								</div>

								{#if sc.id === 'admin'}
									<Switch
										id="scope-admin"
										checked={formScopes.admin}
										onCheckedChange={toggleAdminScope}
									/>
								{:else}
									<Switch
										id="scope-{sc.id}"
										checked={formScopes.admin || formScopes[sc.id]}
										disabled={formScopes.admin}
										onCheckedChange={(c) => (formScopes[sc.id] = c)}
									/>
								{/if}
							</div>
							{#if sc.id === 'admin'}
								<Separator class="my-1" />
							{/if}
						{/each}
					</div>
				</Field.FieldSet>
			</Field.FieldGroup>

			<Dialog.Footer class="pt-2">
				<Button
					type="button"
					variant="outline"
					class="rounded-xl cursor-pointer text-xs"
					onclick={() => (open = false)}
				>
					Cancelar
				</Button>

				<Button
					type="submit"
					class="rounded-xl cursor-pointer text-xs bg-primary text-primary-foreground hover:bg-primary/90 shadow-sm"
					disabled={isSubmitting || !formName.trim()}
				>
					{#if isSubmitting}
						<Loader2Icon data-icon="inline-start" class="animate-spin" />
						Gerando Chave...
					{:else}
						<SparklesIcon data-icon="inline-start" />
						Gerar Chave de API
					{/if}
				</Button>
			</Dialog.Footer>
		</form>
	</Dialog.Content>
</Dialog.Root>
