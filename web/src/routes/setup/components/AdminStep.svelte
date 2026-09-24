<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Label } from "$lib/components/ui/label";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import ArrowRightIcon from "@lucide/svelte/icons/arrow-right";
	import LockIcon from "@lucide/svelte/icons/lock";
	import UserIcon from "@lucide/svelte/icons/user";
	import EyeIcon from "@lucide/svelte/icons/eye";
	import EyeOffIcon from "@lucide/svelte/icons/eye-off";

	let {
		username = $bindable("admin"),
		password = $bindable(""),
		confirmPassword = $bindable(""),
		onnext,
	}: {
		username: string;
		password: string;
		confirmPassword: string;
		onnext: () => void;
	} = $props();

	let showPassword = $state(false);
</script>

<Card.Header>
	<div class="flex items-center gap-3">
		<div class="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
			<ShieldCheckIcon class="h-5 w-5" />
		</div>
		<div>
			<Card.Title>Administrator Security</Card.Title>
			<Card.Description>Create your primary administrator account to secure the network console.</Card.Description>
		</div>
	</div>
</Card.Header>
<Card.Content class="space-y-4">
	<div class="space-y-1.5">
		<Label for="username">Admin Username</Label>
		<div class="relative">
			<UserIcon class="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
			<Input id="username" class="pl-9" bind:value={username} placeholder="admin" />
		</div>
	</div>

	<div class="space-y-1.5">
		<Label for="password">Password (Minimum 8 characters)</Label>
		<div class="relative">
			<LockIcon class="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
			<Input
				id="password"
				type={showPassword ? "text" : "password"}
				class="pl-9 pr-9"
				bind:value={password}
				placeholder="••••••••••••"
			/>
			<button
				type="button"
				class="absolute right-3 top-3 text-muted-foreground hover:text-foreground"
				onclick={() => (showPassword = !showPassword)}
			>
				{#if showPassword}<EyeOffIcon class="h-4 w-4" />{:else}<EyeIcon class="h-4 w-4" />{/if}
			</button>
		</div>
	</div>

	<div class="space-y-1.5">
		<Label for="confirm_password">Confirm Password</Label>
		<div class="relative">
			<LockIcon class="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
			<Input
				id="confirm_password"
				type={showPassword ? "text" : "password"}
				class="pl-9"
				bind:value={confirmPassword}
				placeholder="••••••••••••"
			/>
		</div>
	</div>
</Card.Content>
<Card.Footer class="flex justify-end">
	<Button onclick={onnext} class="gap-2">
		Next: Internet Uplink
		<ArrowRightIcon class="h-4 w-4" />
	</Button>
</Card.Footer>
