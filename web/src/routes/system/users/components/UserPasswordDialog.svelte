<script lang="ts">
	import * as Dialog from "$lib/components/ui/dialog";
	import * as Field from "$lib/components/ui/field";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import KeyIcon from "@lucide/svelte/icons/key";
	import Loader2Icon from "@lucide/svelte/icons/loader-2";
	import { userPasswd } from "$lib/api/client";
	import type { UserInfo } from "$lib/api/types";
	import { toast } from "svelte-sonner";

	let {
		open = $bindable(false),
		user = null,
		onUpdated
	}: {
		open: boolean;
		user: UserInfo | null;
		onUpdated: () => void;
	} = $props();

	let newPassword = $state("");
	let confirmPassword = $state("");
	let isSubmitting = $state(false);

	$effect(() => {
		if (open) {
			newPassword = "";
			confirmPassword = "";
		}
	});

	async function handleSubmit() {
		if (!user) return;
		if (!newPassword) {
			toast.error("Informe a nova senha.");
			return;
		}
		if (newPassword.length < 4) {
			toast.error("A senha deve ter pelo menos 4 caracteres.");
			return;
		}
		if (newPassword !== confirmPassword) {
			toast.error("As senhas informadas não coincidem.");
			return;
		}

		isSubmitting = true;
		try {
			await userPasswd(user.username, newPassword);
			toast.success(`Senha de '${user.username}' atualizada com sucesso!`);
			open = false;
			onUpdated();
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : "Falha ao alterar senha.";
			toast.error(msg);
		} finally {
			isSubmitting = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="sm:max-w-md rounded-2xl">
		<Dialog.Header>
			<Dialog.Title class="text-base font-bold flex items-center gap-2">
				<KeyIcon class="size-5 text-primary" />
				Alterar Senha do Usuário
			</Dialog.Title>
			<Dialog.Description class="text-xs">
				Defina uma nova senha para a conta <strong>{user?.username}</strong>.
			</Dialog.Description>
		</Dialog.Header>

		<form
			onsubmit={(e) => {
				e.preventDefault();
				handleSubmit();
			}}
			class="flex flex-col gap-4 py-2"
		>
			<Field.FieldGroup class="flex flex-col gap-3">
				<!-- Nova Senha -->
				<Field.Field>
					<Field.FieldLabel for="edit-new-password" class="text-xs font-semibold">
						Nova Senha *
					</Field.FieldLabel>
					<Input
						id="edit-new-password"
						type="password"
						placeholder="Nova senha de acesso"
						bind:value={newPassword}
						class="text-xs rounded-xl h-9 bg-background"
					/>
				</Field.Field>

				<!-- Confirmar Senha -->
				<Field.Field>
					<Field.FieldLabel for="edit-confirm-password" class="text-xs font-semibold">
						Confirmar Nova Senha *
					</Field.FieldLabel>
					<Input
						id="edit-confirm-password"
						type="password"
						placeholder="Repita a nova senha"
						bind:value={confirmPassword}
						class="text-xs rounded-xl h-9 bg-background"
					/>
				</Field.Field>
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
					disabled={isSubmitting || !newPassword}
				>
					{#if isSubmitting}
						<Loader2Icon data-icon="inline-start" class="animate-spin" />
						Atualizando...
					{:else}
						<KeyIcon data-icon="inline-start" />
						Salvar Nova Senha
					{/if}
				</Button>
			</Dialog.Footer>
		</form>
	</Dialog.Content>
</Dialog.Root>
