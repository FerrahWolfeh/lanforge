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
	import { eventFeed } from "$lib/stores/events.svelte";
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
			eventFeed.connect();
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
		<Card.Header class="pb-4">
			<Card.Title class="text-lg">Sign in</Card.Title>
			<Card.Description>
				{mode === "password"
					? "Use your account credentials"
					: "Use an API token to authenticate"}
			</Card.Description>
		</Card.Header>

		<Card.Content>
			<form onsubmit={handleSubmit} class="flex flex-col gap-4">
				{#if mode === "password"}
					<!-- Username / password fields -->
					<Field.FieldGroup>
						<Field.Field
							data-invalid={!!errorMsg && mode === "password"}
						>
							<Field.FieldLabel for="username"
								>Username</Field.FieldLabel
							>
							<div class="relative">
								<UserIcon
									class="text-muted-foreground absolute top-1/2 left-3 size-4 -translate-y-1/2"
								/>
								<Input
									id="username"
									type="text"
									autocomplete="username"
									placeholder="admin"
									class="pl-9"
									bind:value={username}
									aria-invalid={!!errorMsg}
									required
								/>
							</div>
						</Field.Field>

						<Field.Field
							data-invalid={!!errorMsg && mode === "password"}
						>
							<Field.FieldLabel for="password"
								>Password</Field.FieldLabel
							>
							<div class="relative">
								<LockIcon
									class="text-muted-foreground absolute top-1/2 left-3 size-4 -translate-y-1/2"
								/>
								<Input
									id="password"
									type={showPassword ? "text" : "password"}
									autocomplete="current-password"
									placeholder="••••••••"
									class="px-9"
									bind:value={password}
									aria-invalid={!!errorMsg}
									required
								/>
								<button
									type="button"
									class="text-muted-foreground hover:text-foreground absolute top-1/2 right-3 -translate-y-1/2 transition-colors"
									onclick={() =>
										(showPassword = !showPassword)}
									aria-label={showPassword
										? "Hide password"
										: "Show password"}
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
					<!-- API key field -->
					<Field.FieldGroup>
						<Field.Field
							data-invalid={!!errorMsg && mode === "apikey"}
						>
							<Field.FieldLabel for="apikey"
								>API Token</Field.FieldLabel
							>
							<div class="relative">
								<KeyIcon
									class="text-muted-foreground absolute top-1/2 left-3 size-4 -translate-y-1/2"
								/>
								<Input
									id="apikey"
									type="password"
									autocomplete="off"
									placeholder="ak_…"
									class="pl-9 font-mono text-sm"
									bind:value={apiKey}
									aria-invalid={!!errorMsg}
									required
								/>
							</div>
							<Field.FieldDescription class="text-xs">
								API tokens are managed via <code
									class="font-mono">lanforge-cli</code
								> on the host.
							</Field.FieldDescription>
						</Field.Field>
					</Field.FieldGroup>
				{/if}

				<!-- Error message -->
				{#if errorMsg}
					<p class="text-destructive text-sm">{errorMsg}</p>
				{/if}

				<!-- Submit -->
				<Button type="submit" class="w-full" disabled={loading}>
					{#if loading}
						<span
							class="size-4 animate-spin rounded-full border-2 border-current border-t-transparent"
						></span>
					{/if}
					{loading ? "Signing in…" : "Sign in"}
				</Button>
			</form>

			<Separator class="my-4" />

			<!-- Mode toggle -->
			<button
				type="button"
				class="text-muted-foreground hover:text-foreground flex w-full items-center justify-center gap-1.5 text-sm transition-colors"
				onclick={() => {
					mode = mode === "password" ? "apikey" : "password";
					errorMsg = "";
				}}
			>
				{#if mode === "password"}
					<KeyIcon class="size-3.5" />
					Use an API token instead
				{:else}
					<UserIcon class="size-3.5" />
					Use username & password instead
				{/if}
			</button>
		</Card.Content>
	</Card.Root>

	<p class="text-muted-foreground mt-6 text-xs">
		Lanforge · LAN orchestration daemon
	</p>
</div>
