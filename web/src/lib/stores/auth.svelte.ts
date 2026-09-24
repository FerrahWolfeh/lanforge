/**
 * Auth store — persists the JWT session token in localStorage.
 * Uses Svelte 5 runes wrapped in a reactive class pattern.
 */

import { me, setClientToken } from '$lib/api/client';
import type { UserInfo } from '$lib/api/types';

const TOKEN_KEY = 'lf_session';

function createAuthStore() {
	let token = $state<string | null>(
		typeof localStorage !== 'undefined' ? localStorage.getItem(TOKEN_KEY) : null
	);
	let user = $state<UserInfo | null>(null);
	let loading = $state(false);

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

		setToken(t: string) {
			token = t;
			setClientToken(t);
		},

		async fetchUser() {
			if (!token) return;
			loading = true;
			try {
				user = await me();
			} catch {
				// token may have expired
				this.clear();
			} finally {
				loading = false;
			}
		},

		clear() {
			token = null;
			user = null;
			setClientToken(null);
		}
	};
}

export const auth = createAuthStore();
