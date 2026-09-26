/**
 * First-run / setup state management.
 */

let isCompleted = false;

export function isSetupCompleted(): boolean {
	return isCompleted;
}

export function markSetupCompleted(): void {
	isCompleted = true;
}
