class SidebarState {
	isCollapsed = $state<boolean>(false);

	constructor() {
		if (typeof window !== "undefined") {
			const saved = localStorage.getItem("lanforge:sidebar:collapsed");
			if (saved !== null) {
				this.isCollapsed = saved === "true";
			}
		}
	}

	toggle() {
		this.isCollapsed = !this.isCollapsed;
		if (typeof window !== "undefined") {
			localStorage.setItem("lanforge:sidebar:collapsed", String(this.isCollapsed));
		}
	}

	expand() {
		this.isCollapsed = false;
		if (typeof window !== "undefined") {
			localStorage.setItem("lanforge:sidebar:collapsed", "false");
		}
	}

	collapse() {
		this.isCollapsed = true;
		if (typeof window !== "undefined") {
			localStorage.setItem("lanforge:sidebar:collapsed", "true");
		}
	}
}

export const sidebarState = new SidebarState();
