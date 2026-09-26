export const ssr = false;
export const prerender = false;

import type { LayoutLoad } from './$types';
import { isRedirect, redirect } from '@sveltejs/kit';
import { authStatus, getSetupStatus, status as getSystemStatus } from '$lib/api/client';
import { auth } from '$lib/stores/auth.svelte';
import { capabilitiesState } from '$lib/stores/capabilities.svelte';
import { isSetupCompleted, markSetupCompleted } from '$lib/stores/setup.svelte';

export const load: LayoutLoad = async ({ url }) => {
	try {
		// 1. First-run / setup inspection (cached once completed)
		if (!isSetupCompleted()) {
			const setup = await getSetupStatus().catch(() => null);
			if (setup?.first_run) {
				if (url.pathname !== '/setup') {
					throw redirect(302, '/setup');
				}
				return {};
			}
			if (setup && !setup.first_run) {
				markSetupCompleted();
			}
		}

		// If setup is already finished, disallow visiting the setup wizard
		if (url.pathname === '/setup') {
			throw redirect(302, '/');
		}

		// 2. Authentication check & early capabilities inspection (parallelized)
		const needsCaps = !capabilitiesState.isLoaded && url.pathname !== '/login';
		const [status, sysStatus] = await Promise.all([
			authStatus(),
			needsCaps ? getSystemStatus().catch(() => null) : Promise.resolve(null)
		]);

		if (sysStatus) {
			capabilitiesState.updateFromStatus(sysStatus);
		}

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
	} catch (e) {
		// Re-throw SvelteKit redirects so the router performs the navigation
		if (
			isRedirect(e) ||
			(e as { status?: number })?.status === 302 ||
			(e as { status?: number })?.status === 307
		) {
			throw e;
		}
		// Network errors / daemon offline — let the layout and pages handle offline state gracefully
	}

	return {};
};
