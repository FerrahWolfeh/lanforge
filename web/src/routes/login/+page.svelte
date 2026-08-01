<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Field from "$lib/components/ui/field";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Badge } from "$lib/components/ui/badge";
	import { Separator } from "$lib/components/ui/separator";
	import { auth } from "$lib/stores/auth.svelte";
	import { login } from "$lib/api/client";
	import { ApiError } from "$lib/api/client";
	import { goto } from "$app/navigation";
	import WifiIcon from "@lucide/svelte/icons/wifi";
	import KeyIcon from "@lucide/svelte/icons/key";
	import UserIcon from "@lucide/svelte/icons/user";
	import LockIcon from "@lucide/svelte/icons/lock";
	import EyeIcon from "@lucide/svelte/icons/eye";
	import EyeOffIcon from "@lucide/svelte/icons/eye-off";

	type Mode = "password" | "apikey";
	let mode = $state<Mode>("password");

	// Password form
	let username = $state("");
	let password = $state("");
	let showPassword = $state(false);

	// API key form
	let apiKey = $state("");

	let rememberMe = $state(false);
	let loading = $state(false);
	let errorMsg = $state("");

	async function handleSubmit(e: SubmitEvent) {
		e.preventDefault();
		errorMsg = "";
		loading = true;

		try {
			const req =
				mode === "apikey"
					? { token: apiKey, remember_me: rememberMe }
					: { username, password, remember_me: rememberMe };

			const res = await login(req);
			auth.setToken(res.token);
			await auth.fetchUser();
			goto("/");
		} catch (err) {
			if (err instanceof ApiError) {
				errorMsg = err.message;
			} else {
				errorMsg = "Could not reach the daemon. Check the connection.";
			}
		} finally {
			loading = false;
		}
	}
</script>

<svelte:head>
	<title>Sign in — Lanforge</title>
</svelte:head>

<div
	class="bg-background flex min-h-screen flex-col items-center justify-center p-4"
>
	<!-- Logo mark -->
	<div class="mb-8 flex flex-col items-center gap-3">
		<div
			class="bg-primary/10 border-primary/20 flex size-14 items-center justify-center rounded-2xl border"
		>
			<WifiIcon class="text-primary size-7" />
		</div>
		<div class="text-center">
			<h1 class="text-foreground text-2xl font-bold tracking-tight">
				Lanforge
			</h1>
			<p class="text-muted-foreground text-sm">
				LAN orchestration console
			</p>
		</div>
	</div>

	<Card.Root class="w-full max-w-sm">
		<Card.Header>
			<Card.Title>Welcome back</Card.Title>
			<Card.Description>
				Sign in to access your homelab console
			</Card.Description>
		</Card.Header>
		<Card.Content class="flex flex-col gap-4">
			<!-- Tab selector -->
			<div class="bg-muted flex rounded-lg p-1">
				<button
					type="button"
					class={[
						"flex-1 rounded-md py-1 text-xs font-medium transition-colors",
						mode === "password"
							? "bg-background text-foreground shadow-sm"
							: "text-muted-foreground hover:text-foreground",
					].join(" ")}
					onclick={() => (mode = "password")}
				>
					Password
				</button>
				<button
					type="button"
					class={[
						"flex-1 rounded-md py-1 text-xs font-medium transition-colors",
						mode === "apikey"
							? "bg-background text-foreground shadow-sm"
							: "text-muted-foreground hover:text-foreground",
					].join(" ")}
					onclick={() => (mode = "apikey")}
				>
					API Key / Token
				</button>
			</div>

			{#if errorMsg}
				<div
					class="border-destructive/30 bg-destructive/10 text-destructive rounded-md border p-3 text-xs"
				>
					{errorMsg}
				</div>
			{/if}

			<form onsubmit={handleSubmit} class="flex flex-col gap-4">
				{#if mode === "password"}
					<Field.FieldGroup class="gap-4">
						<Field.Field>
							<Field.FieldLabel for="username">Username</Field.FieldLabel>
							<div class="relative">
								<UserIcon
									class="text-muted-foreground absolute left-3 top-1/2 size-4 -translate-y-1/2"
								/>
								<Input
									id="username"
									type="text"
									placeholder="admin"
									class="pl-9"
									bind:value={username}
									required
									autocomplete="username"
								/>
							</div>
						</Field.Field>

						<Field.Field>
							<Field.FieldLabel for="password">Password</Field.FieldLabel>
							<div class="relative">
								<LockIcon
									class="text-muted-foreground absolute left-3 top-1/2 size-4 -translate-y-1/2"
								/>
								<Input
									id="password"
									type={showPassword ? "text" : "password"}
									placeholder="••••••••"
									class="pl-9 pr-9"
									bind:value={password}
									required
									autocomplete="current-password"
								/>
								<button
									type="button"
									class="text-muted-foreground hover:text-foreground absolute right-3 top-1/2 -translate-y-1/2"
									onclick={() => (showPassword = !showPassword)}
								>
									{#if showPassword}
										<EyeOffIcon class="size-4" />
									{:else}
										<EyeIcon class="size-4" />
									{/if}
								</button>
							</div>
						</Field.Field>
					</Field.FieldGroup>
				{:else}
					<Field.FieldGroup class="gap-4">
						<Field.Field>
							<Field.FieldLabel for="apikey">API Key / Token</Field.FieldLabel>
							<div class="relative">
								<KeyIcon
									class="text-muted-foreground absolute left-3 top-1/2 size-4 -translate-y-1/2"
								/>
								<Input
									id="apikey"
									type="password"
									placeholder="lf_sec_..."
									class="font-mono pl-9 text-xs"
									bind:value={apiKey}
									required
								/>
							</div>
							<Field.FieldDescription>
								Bearer token generated from CLI or config
							</Field.FieldDescription>
						</Field.Field>
					</Field.FieldGroup>
				{/if}

				<div class="flex items-center gap-2">
					<input
						type="checkbox"
						id="remember"
						bind:checked={rememberMe}
						class="border-input size-4 rounded"
					/>
					<label
						for="remember"
						class="text-muted-foreground cursor-pointer text-xs"
					>
						Remember this session
					</label>
				</div>

				<Button type="submit" class="w-full" disabled={loading}>
					{#if loading}
						<span
							class="mr-2 size-4 animate-spin rounded-full border-2 border-current border-t-transparent"
						></span>
						Signing in...
					{:else}
						Sign in
					{/if}
				</Button>
			</form>
		</Card.Content>
	</Card.Root>
</div>
