import tailwindcss from '@tailwindcss/vite';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig, loadEnv } from 'vite';

export default defineConfig(({ mode }) => {
	const env = loadEnv(mode, process.cwd(), '');
	const target = env.VITE_API_TARGET || 'http://192.168.254.1:8096';

	return {
		plugins: [
			tailwindcss(),
			sveltekit()
		],
		server: {
			proxy: {
				'/api': {
					target,
					changeOrigin: true,
					ws: true
				}
			}
		}
	};
});
