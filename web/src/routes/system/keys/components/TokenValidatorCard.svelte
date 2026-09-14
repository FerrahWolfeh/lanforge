<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Badge } from "$lib/components/ui/badge";
	import TerminalIcon from "@lucide/svelte/icons/terminal";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import CheckCircle2Icon from "@lucide/svelte/icons/check-circle-2";
	import XCircleIcon from "@lucide/svelte/icons/x-circle";
	import Loader2Icon from "@lucide/svelte/icons/loader-2";
	import { validateToken } from "$lib/api/client";
	import { toast } from "svelte-sonner";

	let testTokenInput = $state("");
	let isValidating = $state(false);
	let validationResult = $state<{ valid: boolean; checked: boolean } | null>(null);

	async function handleValidateToken() {
		const trimmed = testTokenInput.trim();
		if (!trimmed) {
			toast.error("Informe um token para validação.");
			return;
		}
		isValidating = true;
		validationResult = null;
		try {
			const res = await validateToken(trimmed);
			validationResult = { valid: res.valid, checked: true };
			if (res.valid) {
				toast.success("Token ativo e válido no sistema!");
			} else {
				toast.error("Token inválido, inexistente ou expirado.");
			}
		} catch (err: unknown) {
			validationResult = { valid: false, checked: true };
			const msg = err instanceof Error ? err.message : "Falha na checagem.";
			toast.error(msg);
		} finally {
			isValidating = false;
		}
	}
</script>

<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
	<!-- Integration Quick Guide -->
	<Card.Root class="rounded-2xl border-border/70 bg-card shadow-xs">
		<Card.Header class="pb-3">
			<Card.Title class="text-sm font-bold flex items-center gap-2 text-foreground">
				<TerminalIcon class="size-4 text-primary" />
				Como Utilizar na Prática
			</Card.Title>
			<Card.Description class="text-xs">
				Exemplos de autenticação para automações com cURL ou na CLI do Lanforge.
			</Card.Description>
		</Card.Header>
		<Card.Content class="flex flex-col gap-3">
			<div class="flex flex-col gap-1">
				<span class="text-[11px] font-semibold text-muted-foreground">Exemplo cURL HTTP:</span>
				<div class="p-2.5 rounded-xl bg-muted/40 border border-border/60 font-mono text-[11px] text-foreground break-all select-all">
					curl -H "Authorization: Bearer lf_ak_..." \
					<br />&nbsp;&nbsp;http://&lt;ip-lanforge&gt;:3000/api/v1/status
				</div>
			</div>

			<div class="flex flex-col gap-1">
				<span class="text-[11px] font-semibold text-muted-foreground">Exemplo CLI Lanforge:</span>
				<div class="p-2.5 rounded-xl bg-muted/40 border border-border/60 font-mono text-[11px] text-foreground break-all select-all">
					lanforge --token lf_ak_... status
				</div>
			</div>
		</Card.Content>
	</Card.Root>

	<!-- Token Tester / Validator -->
	<Card.Root class="rounded-2xl border-border/70 bg-card shadow-xs">
		<Card.Header class="pb-3">
			<Card.Title class="text-sm font-bold flex items-center gap-2 text-foreground">
				<ShieldCheckIcon class="size-4 text-primary" />
				Validador de Token
			</Card.Title>
			<Card.Description class="text-xs">
				Teste se um token específico é reconhecido e está atualmente ativo no daemon.
			</Card.Description>
		</Card.Header>
		<Card.Content class="flex flex-col gap-3">
			<div class="flex flex-col gap-1.5">
				<Input
					placeholder="Cole o token (lf_ak_... ou JWT) para testar..."
					bind:value={testTokenInput}
					class="text-xs font-mono rounded-xl h-9 bg-background"
				/>
			</div>

			<div class="flex items-center justify-between gap-2">
				<Button
					variant="outline"
					size="sm"
					class="rounded-xl cursor-pointer text-xs"
					onclick={handleValidateToken}
					disabled={isValidating || !testTokenInput.trim()}
				>
					{#if isValidating}
						<Loader2Icon data-icon="inline-start" class="animate-spin" />
						Validando...
					{:else}
						<ShieldCheckIcon data-icon="inline-start" />
						Checar Token
					{/if}
				</Button>

				{#if validationResult?.checked}
					{#if validationResult.valid}
						<Badge variant="outline" class="text-xs text-emerald-600 dark:text-emerald-400 border-emerald-500/30 bg-emerald-500/10">
							<CheckCircle2Icon class="size-3.5 mr-1" />
							Token Válido
						</Badge>
					{:else}
						<Badge variant="destructive" class="text-xs">
							<XCircleIcon class="size-3.5 mr-1" />
							Token Inválido ou Expirado
						</Badge>
					{/if}
				{/if}
			</div>
		</Card.Content>
	</Card.Root>
</div>
