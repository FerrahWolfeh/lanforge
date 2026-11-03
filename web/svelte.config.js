import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	preprocess: vitePreprocess(),
	kit: {
		adapter: adapter({
			pages: 'build',
			assets: 'build',
			fallback: 'index.html',
			precompress: false,
			strict: true
		}),
		// Each build gets its own version name (build time); an open tab checks
		// `_app/version.json` and offers a reload once the daemon serves a newer WebUI.
		version: { pollInterval: 60_000 }
	}
};

export default config;
