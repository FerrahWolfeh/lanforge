<script lang="ts">
	import { onDestroy, onMount } from "svelte";
	import * as Dialog from "$lib/components/ui/dialog";
	import * as Field from "$lib/components/ui/field";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import { setReauthPrompt } from "$lib/api/client";

	// Global prompt for sensitive actions: the API client opens it when the server asks
	// the session to re-enter its password, then retries the action.
	let open = $state(false);
	let password = $state("");
	let error = $state<string | undefined>(undefined);
	let resolver: ((value: string | null) => void) | null = null;

	function settle(value: string | null) {
		const resolve = resolver;
		resolver = null;
		open = false;
		password = "";
		resolve?.(value);
	}

	onMount(() => {
		setReauthPrompt(
			(err) =>
				new Promise((resolve) => {
					// A second prompt while one is open supersedes it.
					resolver?.(null);
					resolver = resolve;
					error = err;
					password = "";
					open = true;
				})
		);
	});

	onDestroy(() => setReauthPrompt(null));
</script>

<Dialog.Root
	bind:open
	onOpenChange={(isOpen) => {
		if (!isOpen && resolver) settle(null);
	}}
>
	<Dialog.Content class="sm:max-w-sm rounded-2xl">
		<Dialog.Header>
			<Dialog.Title class="text-base font-bold flex items-center gap-2">
				<ShieldCheckIcon class="size-5 text-primary" />
				Confirm Your Password
			</Dialog.Title>
			<Dialog.Description class="text-xs">
				This action changes accounts or grants lasting access. Enter your password to continue.
			</Dialog.Description>
		</Dialog.Header>

		<form
			onsubmit={(e) => {
				e.preventDefault();
				if (password) settle(password);
			}}
			class="flex flex-col gap-4 py-2"
		>
			<Field.Field>
				<Field.FieldLabel for="reauth-password" class="text-xs font-semibold">
					Your Password
				</Field.FieldLabel>
				<Input
					id="reauth-password"
					type="password"
					autocomplete="current-password"
					placeholder="Current password"
					bind:value={password}
					class="text-xs rounded-xl h-9 bg-background"
				/>
				{#if error}
					<p class="text-xs text-destructive">{error}</p>
				{/if}
			</Field.Field>

			<Dialog.Footer class="pt-2">
				<Button
					type="button"
					variant="outline"
					class="rounded-xl cursor-pointer text-xs"
					onclick={() => settle(null)}
				>
					Cancel
				</Button>
				<Button
					type="submit"
					class="rounded-xl cursor-pointer text-xs bg-primary text-primary-foreground hover:bg-primary/90 shadow-sm"
					disabled={!password}
				>
					<ShieldCheckIcon data-icon="inline-start" />
					Confirm
				</Button>
			</Dialog.Footer>
		</form>
	</Dialog.Content>
</Dialog.Root>
