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
			toast.error("Please enter a username.");
			return;
		}
		if (trimmedUser.length < 2) {
			toast.error("Username must be at least 2 characters.");
			return;
		}
		if (!password) {
			toast.error("Please enter a password.");
			return;
		}
		if (password.length < 4) {
			toast.error("Password must be at least 4 characters.");
			return;
		}
		if (password !== confirmPassword) {
			toast.error("Passwords do not match.");
			return;
		}

		isSubmitting = true;
		try {
			await userCreate(trimmedUser, password, role);
			toast.success(`User '${trimmedUser}' created successfully!`);
			open = false;
			onCreated();
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : "Failed to create user.";
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
				New User
			</Dialog.Title>
			<Dialog.Description class="text-xs">
				Create a local user account for administrative or operational access to Lanforge.
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
				<!-- Username -->
				<Field.Field>
					<Field.FieldLabel for="new-username" class="text-xs font-semibold">
						Username *
					</Field.FieldLabel>
					<Input
						id="new-username"
						placeholder="e.g. operator1, sysadmin"
						bind:value={username}
						class="text-xs rounded-xl h-9 bg-background"
					/>
				</Field.Field>

				<!-- Role -->
				<Field.Field>
					<Field.FieldLabel for="new-user-role" class="text-xs font-semibold">
						Role & Permissions
					</Field.FieldLabel>
					<select
						id="new-user-role"
						bind:value={role}
						class="w-full h-9 text-xs rounded-xl bg-background border border-input px-3 text-foreground outline-none focus-visible:ring-1 focus-visible:ring-ring"
					>
						<option value="operator">Operator (Device, network, and DNS management)</option>
						<option value="admin">Administrator (Unrestricted access to config & database)</option>
						<option value="viewer">Viewer (Read-only access to metrics & status)</option>
					</select>
				</Field.Field>

				<!-- Password -->
				<Field.Field>
					<Field.FieldLabel for="new-password" class="text-xs font-semibold">
						Password *
					</Field.FieldLabel>
					<Input
						id="new-password"
						type="password"
						placeholder="Secure password"
						bind:value={password}
						class="text-xs rounded-xl h-9 bg-background"
					/>
				</Field.Field>

				<!-- Confirm Password -->
				<Field.Field>
					<Field.FieldLabel for="new-confirm-password" class="text-xs font-semibold">
						Confirm Password *
					</Field.FieldLabel>
					<Input
						id="new-confirm-password"
						type="password"
						placeholder="Repeat password"
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
					Cancel
				</Button>

				<Button
					type="submit"
					class="rounded-xl cursor-pointer text-xs bg-primary text-primary-foreground hover:bg-primary/90 shadow-sm"
					disabled={isSubmitting || !username.trim() || !password}
				>
					{#if isSubmitting}
						<Loader2Icon data-icon="inline-start" class="animate-spin" />
						Creating...
					{:else}
						<UserPlusIcon data-icon="inline-start" />
						Create User
					{/if}
				</Button>
			</Dialog.Footer>
		</form>
	</Dialog.Content>
</Dialog.Root>
