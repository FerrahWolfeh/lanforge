export const ssr = false;
export const prerender = false;

import type { LayoutLoad } from './$types';
import { isRedirect, redirect } from '@sveltejs/kit';
import { authStatus, getSetupStatus, status as getSystemStatus } from '$lib/api/client';
import { auth } from '$lib/stores/auth.svelte';
import { capabilitiesState } from '$lib/stores/capabilities.svelte';

export const load: LayoutLoad = async ({ url }) => {
	try {
		// 1. First-run / setup inspection
		const setup = await getSetupStatus().catch(() => null);
		if (setup?.first_run) {
			if (url.pathname !== '/setup') {
				throw redirect(302, '/setup');
			}
			return {};
		}

		// If setup is already finished, disallow visiting the setup wizard
		if (url.pathname === '/setup') {
			throw redirect(302, '/');
		}

		// 2. Authentication check
		const status = await authStatus();

		if (status.auth_required) {
			if (!status.authenticated) {
				// Not authenticated: clear any stale token and redirect to login
				auth.clear();
				if (url.pathname !== '/login') {
					throw redirect(302, '/login');
				}
			} else {
				// Authenticated: ensure user profile is populated
				if (!auth.user) {
					await auth.fetchUser();
				}
				// If currently on login page, redirect back to dashboard
				if (url.pathname === '/login') {
					throw redirect(302, '/');
				}
			}
		} else {
			// Authentication not required on this server
			if (url.pathname === '/login') {
				throw redirect(302, '/');
			}
		}

		// 3. Early capabilities inspection
		if (url.pathname !== '/setup' && url.pathname !== '/login') {
			const sysStatus = await getSystemStatus().catch(() => null);
			if (sysStatus) {
				capabilitiesState.updateFromStatus(sysStatus);
			}
		}
	} catch (e) {
		// Re-throw SvelteKit redirects so the router performs the navigation
		if (isRedirect(e) || (e as { status?: number })?.status === 302 || (e as { status?: number })?.status === 307) {
			throw e;
		}
		// Network errors / daemon offline — let the layout and pages handle offline state gracefully
	}

	return {};
};
