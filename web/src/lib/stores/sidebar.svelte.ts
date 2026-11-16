const STORAGE_KEY = "lanforge:sidebar:collapsed";

function loadCollapsed(): boolean {
	try {
		return localStorage.getItem(STORAGE_KEY) === "true";
	} catch {
		// storage blocked: start expanded
		return false;
	}
}

class SidebarState {
	isCollapsed = $state<boolean>(false);

	constructor() {
		if (typeof window !== "undefined") {
			this.isCollapsed = loadCollapsed();
		}
	}

	private set(collapsed: boolean) {
		this.isCollapsed = collapsed;
		if (typeof window === "undefined") return;
		try {
			localStorage.setItem(STORAGE_KEY, String(collapsed));
		} catch {
			// storage blocked: the choice lasts for this page load
		}
	}

	toggle() {
		this.set(!this.isCollapsed);
	}

	expand() {
		this.set(false);
	}

	collapse() {
		this.set(true);
	}
}

export const sidebarState = new SidebarState();
