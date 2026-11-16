/**
 * Saves text content as a file download in the browser.
 */
export function downloadBlob(content: string, filename: string, mime: string): void {
	const url = URL.createObjectURL(new Blob([content], { type: mime }));
	const a = document.createElement("a");
	a.href = url;
	a.download = filename;
	document.body.appendChild(a);
	a.click();
	document.body.removeChild(a);
	URL.revokeObjectURL(url);
}
