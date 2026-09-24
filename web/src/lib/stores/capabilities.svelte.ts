import type { ServerCapabilities, StatusResponse } from "$lib/api/types";
import { dev } from "$app/environment";

const DEV_OVERRIDE_STORAGE_KEY = "lanforge:dev:caps_override";

function getInitialDebugMode(): boolean {
	if (!dev || typeof sessionStorage === "undefined") return false;
	try {
		return sessionStorage.getItem(DEV_OVERRIDE_STORAGE_KEY) === "1";
	} catch {
		return false;
	}
}

class CapabilitiesState {
	serverCaps = $state<ServerCapabilities | null>(null);
	isLoaded = $state<boolean>(false);
	debugMode = $state<boolean>(getInitialDebugMode());

	get compiled(): string[] {
		return this.serverCaps?.compiled ?? [];
	}

	get enabled(): string[] {
		return this.serverCaps?.enabled ?? [];
	}

	/**
	 * Explicitly toggle or set dev override mode.
	 */
	setDebugMode(enabled: boolean) {
		if (!dev) return;
		this.debugMode = enabled;
		try {
			if (typeof sessionStorage !== "undefined") {
				if (enabled) {
					sessionStorage.setItem(DEV_OVERRIDE_STORAGE_KEY, "1");
				} else {
					sessionStorage.removeItem(DEV_OVERRIDE_STORAGE_KEY);
				}
			}
		} catch {}
	}

	/**
	 * Toggles dev override mode on or off.
	 */
	toggleDebugMode() {
		this.setDebugMode(!this.debugMode);
	}

	/**
	 * Checks if a capability is strictly compiled into the running binary.
	 * Not overridden by debug mode.
	 */
	isActualCompiled(cap: string): boolean {
		if (!this.serverCaps) return true;
		const norm = cap.toLowerCase();
		return this.serverCaps.compiled.some((c) => c.toLowerCase() === norm);
	}

	/**
	 * Checks if a capability is strictly enabled on the running daemon.
	 * Not overridden by debug mode.
	 */
	isActualEnabled(cap: string): boolean {
		if (!this.serverCaps) return true;
		const norm = cap.toLowerCase();
		return this.serverCaps.enabled.some((c) => c.toLowerCase() === norm);
	}

	/**
	 * Checks if any of the given capabilities are strictly enabled on the running daemon.
	 */
	isAnyActualEnabled(caps: string[]): boolean {
		if (!this.serverCaps) return true;
		return caps.some((c) => this.isActualEnabled(c));
	}

	/**
	 * Checks if a capability is compiled into the running binary.
	 * Returns true if debugMode is active in dev or if capabilities have not yet loaded.
	 */
	isCompiled(cap: string): boolean {
		if (this.debugMode) return true;
		return this.isActualCompiled(cap);
	}

	/**
	 * Checks if a capability is both compiled and enabled in runtime configuration.
	 * Returns true if debugMode is active in dev or if capabilities have not yet loaded.
	 */
	isEnabled(cap: string): boolean {
		if (this.debugMode) return true;
		return this.isActualEnabled(cap);
	}

	/**
	 * Checks if any of the provided capabilities are enabled.
	 * Returns true if debugMode is active in dev.
	 */
	isAnyEnabled(caps: string[]): boolean {
		if (this.debugMode) return true;
		return caps.some((c) => this.isEnabled(c));
	}

	/**
	 * Updates state from a StatusResponse payload.
	 */
	updateFromStatus(status?: StatusResponse | null) {
		if (!status) return;
		const caps =
			status.server_caps ??
			(status.capabilities && "compiled" in status.capabilities
				? (status.capabilities as ServerCapabilities)
				: null);

		if (caps && Array.isArray(caps.compiled) && Array.isArray(caps.enabled)) {
			this.serverCaps = caps;
			this.isLoaded = true;
		}
	}

	setCapabilities(caps: ServerCapabilities) {
		this.serverCaps = caps;
		this.isLoaded = true;
	}
}

export const capabilitiesState = new CapabilitiesState();
