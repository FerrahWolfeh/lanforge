<script lang="ts">
	import * as Dialog from "$lib/components/ui/dialog";
	import * as Field from "$lib/components/ui/field";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import UserPlusIcon from "@lucide/svelte/icons/user-plus";
	import Loader2Icon from "@lucide/svelte/icons/loader-2";
	import { userCreate } from "$lib/api/client";
	import type { UserRole } from "$lib/api/types";
	import { toast } from "svelte-sonner";

	let {
		open = $bindable(false),
		onCreated
	}: {
		open: boolean;
		onCreated: () => void;
	} = $props();

	let username = $state("");
	let password = $state("");
	let confirmPassword = $state("");
	let role = $state<UserRole>("operator");
	let isSubmitting = $state(false);

	$effect(() => {
		if (open) {
			username = "";
			password = "";
			confirmPassword = "";
			role = "operator";
		}
	});

	async function handleSubmit() {
		const trimmedUser = username.trim();
		if (!trimmedUser) {
			toast.error("Informe o nome de usuário.");
			return;
		}
		if (trimmedUser.length < 2) {
			toast.error("O nome de usuário deve ter pelo menos 2 caracteres.");
			return;
		}
		if (!password) {
			toast.error("Informe uma senha.");
			return;
		}
		if (password.length < 4) {
			toast.error("A senha deve ter pelo menos 4 caracteres.");
			return;
		}
		if (password !== confirmPassword) {
			toast.error("As senhas informadas não coincidem.");
			return;
		}

		isSubmitting = true;
		try {
			await userCreate(trimmedUser, password, role);
			toast.success(`Usuário '${trimmedUser}' criado com sucesso!`);
			open = false;
			onCreated();
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : "Falha ao criar usuário.";
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
				<UserPlusIcon class="size-5 text-primary" />
				Novo Usuário
			</Dialog.Title>
			<Dialog.Description class="text-xs">
				Crie uma conta local para acesso administrativo ou operacional ao painel do Lanforge.
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
				<!-- Usuário -->
				<Field.Field>
					<Field.FieldLabel for="new-username" class="text-xs font-semibold">
						Nome de Usuário *
					</Field.FieldLabel>
					<Input
						id="new-username"
						placeholder="Ex: operador1, analista"
						bind:value={username}
						class="text-xs rounded-xl h-9 bg-background"
					/>
				</Field.Field>

				<!-- Nível de Acesso -->
				<Field.Field>
					<Field.FieldLabel for="new-user-role" class="text-xs font-semibold">
						Nível de Acesso (Perfil)
					</Field.FieldLabel>
					<select
						id="new-user-role"
						bind:value={role}
						class="w-full h-9 text-xs rounded-xl bg-background border border-input px-3 text-foreground outline-none focus-visible:ring-1 focus-visible:ring-ring"
					>
						<option value="operator">Operador (Acesso a dispositivos, rede e DNS)</option>
						<option value="admin">Administrador (Acesso irrestrito a configurações e banco)</option>
						<option value="viewer">Visualizador (Somente visualização de métricas e status)</option>
					</select>
				</Field.Field>

				<!-- Senha -->
				<Field.Field>
					<Field.FieldLabel for="new-password" class="text-xs font-semibold">
						Senha *
					</Field.FieldLabel>
					<Input
						id="new-password"
						type="password"
						placeholder="Senha segura"
						bind:value={password}
						class="text-xs rounded-xl h-9 bg-background"
					/>
				</Field.Field>

				<!-- Confirmar Senha -->
				<Field.Field>
					<Field.FieldLabel for="new-confirm-password" class="text-xs font-semibold">
						Confirmar Senha *
					</Field.FieldLabel>
					<Input
						id="new-confirm-password"
						type="password"
						placeholder="Repita a senha"
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
					disabled={isSubmitting || !username.trim() || !password}
				>
					{#if isSubmitting}
						<Loader2Icon data-icon="inline-start" class="animate-spin" />
						Criando...
					{:else}
						<UserPlusIcon data-icon="inline-start" />
						Criar Usuário
					{/if}
				</Button>
			</Dialog.Footer>
		</form>
	</Dialog.Content>
</Dialog.Root>
