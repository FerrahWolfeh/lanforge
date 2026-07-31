export const ssr = false;
export const prerender = false;

import type { LayoutLoad } from './$types';
import { redirect } from '@sveltejs/kit';
import { authStatus } from '$lib/api/client';
import { auth } from '$lib/stores/auth.svelte';

export const load: LayoutLoad = async ({ url }) => {
	// Skip auth check on the login page itself
	if (url.pathname === '/login') return {};

	try {
		const status = await authStatus();

		if (status.auth_required && !status.authenticated && !auth.token) {
			throw redirect(302, '/login');
		}

		// If authenticated via cookie/token in status but store is empty, fetch profile
		if (status.authenticated && !auth.user) {
			await auth.fetchUser();
		}
	} catch (e) {
		// Re-throw SvelteKit redirects
		if (e instanceof Response || (e as { status?: number })?.status === 302) throw e;
		// Network errors / daemon offline — let the page handle it gracefully
	}

	return {};
};
