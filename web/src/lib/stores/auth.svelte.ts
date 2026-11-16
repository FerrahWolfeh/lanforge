/**
 * Auth store — persists the JWT session token in localStorage.
 * Uses Svelte 5 runes wrapped in a reactive class pattern.
 */

import { ApiError, getToken, logout, me, onTokenChange, setClientToken } from '$lib/api/client';
import type { Permission, SessionUser } from '$lib/api/types';

function createAuthStore() {
	// The client owns the token; this copy only makes it reactive.
	let token = $state<string | null>(getToken());
	let user = $state<SessionUser | null>(null);
	let loading = $state(false);
	onTokenChange((t) => {
		token = t;
		if (t === null) user = null;
	});

	return {
		get token() {
			return token;
		},
		get user() {
			return user;
		},
		get loading() {
			return loading;
		},
		get authenticated() {
			return token !== null;
		},

		/**
		 * Whether the server grants `permission` to this session, to hide actions it would
		 * refuse. Without a user (auth off) or without the list (older daemon) everything is
		 * shown: the server still enforces.
		 */
		can(permission: Permission): boolean {
			const granted = user?.permissions;
			return granted === undefined || granted.includes(permission);
		},

		setToken(t: string) {
			setClientToken(t);
		},

		/** Loads the profile; false when it could not be loaded (the session is kept unless rejected). */
		async fetchUser(): Promise<boolean> {
			if (!token) return false;
			loading = true;
			try {
				user = await me();
				return true;
			} catch (err) {
				// Only a rejected token ends the session; a network or server error must not.
				if (err instanceof ApiError && err.status === 401) this.clear();
				return false;
			} finally {
				loading = false;
			}
		},

		/** Ends the session on the daemon (which may be unreachable) and forgets it here. */
		async signOut() {
			try {
				await logout();
			} catch {
				// the local session ends either way
			}
			this.clear();
		},

		clear() {
			setClientToken(null);
		}
	};
}

export const auth = createAuthStore();
