<script lang="ts">
	import { onMount } from "svelte";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { auth } from "$lib/stores/auth.svelte";
	import { login, ApiError } from "$lib/api/client";
	import { goto } from "$app/navigation";
	import ModeToggle from "$lib/components/ModeToggle.svelte";

	import WifiIcon from "@lucide/svelte/icons/wifi";
	import KeyIcon from "@lucide/svelte/icons/key";
	import UserIcon from "@lucide/svelte/icons/user";
	import LockIcon from "@lucide/svelte/icons/lock";
	import EyeIcon from "@lucide/svelte/icons/eye";
	import EyeOffIcon from "@lucide/svelte/icons/eye-off";
	import ArrowRightIcon from "@lucide/svelte/icons/arrow-right";
	import Loader2Icon from "@lucide/svelte/icons/loader-2";
	import ShieldAlertIcon from "@lucide/svelte/icons/shield-alert";

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

	onMount(() => {
		if (auth.authenticated) {
			goto("/");
		}
	});

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
	class="relative flex min-h-[100dvh] w-full items-center justify-center bg-background p-4 sm:p-6 lg:p-8 overflow-hidden"
>
	<!-- Ambient Backdrop Glow (inspired by prod-server) -->
	<div class="pointer-events-none absolute inset-0 overflow-hidden">
		<div
			class="absolute -top-32 left-1/2 -translate-x-1/2 h-[450px] w-[520px] rounded-full bg-primary/10 blur-[130px]"
		></div>
		<div
			class="absolute -bottom-32 left-1/2 -translate-x-1/2 h-[400px] w-[460px] rounded-full bg-primary/5 blur-[110px]"
		></div>
	</div>

	<!-- Top-Right Floating Theme Toggle -->
	<div class="absolute top-4 right-4 z-20">
		<ModeToggle />
	</div>

	<!-- Centered Main Auth Card -->
	<div
		class="relative z-10 w-full max-w-[420px] rounded-2xl sm:rounded-3xl border border-border/80 bg-card/95 p-6 sm:p-8 shadow-2xl backdrop-blur-xl transition-all"
	>
		<!-- Header: Branding integrated inside the card -->
		<div class="flex flex-col items-center text-center gap-3 pb-6">
			<div
				class="flex size-13 items-center justify-center rounded-2xl bg-primary/10 border border-primary/20 text-primary shadow-xs transition-transform duration-300 hover:scale-105"
			>
				<WifiIcon class="size-6 text-primary" />
			</div>
			<div class="space-y-1">
				<h1 class="text-xl sm:text-2xl font-bold tracking-tight text-foreground">
					Lanforge
				</h1>
				<p class="text-xs text-muted-foreground">
					Enter your credentials to access the homelab console
				</p>
			</div>
		</div>

		<div class="space-y-5">
			<!-- Auth Mode Switcher Tabs -->
			<div class="bg-muted/60 border border-border/50 grid grid-cols-2 rounded-xl p-1 gap-1">
				<button
					type="button"
					class={[
						"flex items-center justify-center gap-1.5 rounded-lg py-1.5 text-xs font-medium transition-all duration-200",
						mode === "password"
							? "bg-background text-foreground shadow-xs"
							: "text-muted-foreground hover:text-foreground",
					].join(" ")}
					onclick={() => (mode = "password")}
				>
					<UserIcon class="size-3.5" />
					<span>Password</span>
				</button>
				<button
					type="button"
					class={[
						"flex items-center justify-center gap-1.5 rounded-lg py-1.5 text-xs font-medium transition-all duration-200",
						mode === "apikey"
							? "bg-background text-foreground shadow-xs"
							: "text-muted-foreground hover:text-foreground",
					].join(" ")}
					onclick={() => (mode = "apikey")}
				>
					<KeyIcon class="size-3.5" />
					<span>API Key / Token</span>
				</button>
			</div>

			<!-- Error Alert Banner -->
			{#if errorMsg}
				<div
					class="flex items-start gap-2.5 rounded-xl border border-destructive/30 bg-destructive/10 p-3 text-xs text-destructive"
				>
					<ShieldAlertIcon class="size-4 shrink-0 mt-0.5" />
					<span class="leading-relaxed">{errorMsg}</span>
				</div>
			{/if}

			<!-- Form Body -->
			<form onsubmit={handleSubmit} class="space-y-4">
				{#if mode === "password"}
					<div class="space-y-3.5">
						<!-- Username -->
						<div class="space-y-1.5">
							<label for="username" class="text-xs font-medium text-foreground/90">
								Username
							</label>
							<div class="relative">
								<UserIcon
									class="text-muted-foreground absolute left-3.5 top-1/2 -translate-y-1/2 size-4 pointer-events-none"
								/>
								<Input
									id="username"
									type="text"
									placeholder="admin"
									class="h-11 rounded-xl pl-10 bg-muted/30 border-border/70 focus-visible:ring-primary/40 text-sm"
									bind:value={username}
									required
									autocomplete="username"
									disabled={loading}
								/>
							</div>
						</div>

						<!-- Password -->
						<div class="space-y-1.5">
							<label for="password" class="text-xs font-medium text-foreground/90">
								Password
							</label>
							<div class="relative">
								<LockIcon
									class="text-muted-foreground absolute left-3.5 top-1/2 -translate-y-1/2 size-4 pointer-events-none"
								/>
								<Input
									id="password"
									type={showPassword ? "text" : "password"}
									placeholder="••••••••"
									class="h-11 rounded-xl pl-10 pr-10 bg-muted/30 border-border/70 focus-visible:ring-primary/40 text-sm"
									bind:value={password}
									required
									autocomplete="current-password"
									disabled={loading}
								/>
								<button
									type="button"
									class="text-muted-foreground hover:text-foreground absolute right-3.5 top-1/2 -translate-y-1/2 p-0.5 transition-colors focus:outline-none"
									onclick={() => (showPassword = !showPassword)}
									aria-label={showPassword ? "Hide password" : "Show password"}
								>
									{#if showPassword}
										<EyeOffIcon class="size-4" />
									{:else}
										<EyeIcon class="size-4" />
									{/if}
								</button>
							</div>
						</div>
					</div>
				{:else}
					<div class="space-y-2">
						<label for="apikey" class="text-xs font-medium text-foreground/90">
							API Key / Bearer Token
						</label>
						<div class="relative">
							<KeyIcon
								class="text-muted-foreground absolute left-3.5 top-1/2 -translate-y-1/2 size-4 pointer-events-none"
							/>
							<Input
								id="apikey"
								type="password"
								placeholder="lf_sec_..."
								class="font-mono h-11 rounded-xl pl-10 bg-muted/30 border-border/70 focus-visible:ring-primary/40 text-xs"
								bind:value={apiKey}
								required
								disabled={loading}
							/>
						</div>
						<p class="text-[11px] text-muted-foreground">
							Bearer token generated via Lanforge CLI or configuration
						</p>
					</div>
				{/if}

				<!-- Remember Me -->
				<div class="flex items-center gap-2 pt-0.5">
					<input
						type="checkbox"
						id="remember"
						bind:checked={rememberMe}
						class="accent-primary size-4 rounded border-border cursor-pointer"
					/>
					<label
						for="remember"
						class="text-xs text-muted-foreground hover:text-foreground cursor-pointer select-none"
					>
						Remember this session
					</label>
				</div>

				<!-- Submit Button -->
				<Button
					type="submit"
					class="h-11 w-full rounded-xl text-sm font-semibold shadow-md gap-2 mt-2 transition-all hover:opacity-95"
					disabled={loading || (mode === "password" ? (!username || !password) : !apiKey)}
				>
					{#if loading}
						<Loader2Icon class="size-4 animate-spin" />
						<span>Signing in...</span>
					{:else}
						<span>Sign in</span>
						<ArrowRightIcon class="size-4" />
					{/if}
				</Button>
			</form>
		</div>

		<!-- Footer Card Note -->
		<div
			class="mt-6 pt-4 border-t border-border/50 flex items-center justify-center gap-2 text-[11px] text-muted-foreground/80"
		>
			<span class="size-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
			<span>Lanforge &bull; LAN Orchestrator</span>
		</div>
	</div>
</div>
