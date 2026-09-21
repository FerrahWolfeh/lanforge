import { QueryClient } from '@tanstack/svelte-query';

export const queryClient = new QueryClient({
	defaultOptions: {
		queries: {
			staleTime: 5_000,
			gcTime: 60_000,
			refetchOnWindowFocus: true,
			retry: 1,
		},
	},
});
