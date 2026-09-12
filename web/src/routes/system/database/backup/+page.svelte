<script lang="ts">
	import { toast } from "svelte-sonner";
	import {
		exportSystemConfig,
		exportSystemConfigToml,
		importSystemConfig,
	} from "$lib/api/client";
	import type {
		SystemConfigExport,
		SystemConfigImportResponse,
	} from "$lib/api/types";
	import DbBackupTab from "../components/DbBackupTab.svelte";
	import DbImportResultModal from "../components/DbImportResultModal.svelte";
	import { dbState, formatBytes } from "../dbState.svelte";

	let exporting = $state(false);
	let exportingToml = $state(false);
	let importing = $state(false);

	let importFileInput = $state<HTMLInputElement | null>(null);
	let selectedFile = $state<File | null>(null);
	let importOverwrite = $state(false);
	let importResult = $state<SystemConfigImportResponse | null>(null);
	let showImportResultDialog = $state(false);

	async function handleExport() {
		exporting = true;
		try {
			const config = await exportSystemConfig();
			const jsonStr = JSON.stringify(config, null, 2);
			const blob = new Blob([jsonStr], { type: "application/json" });
			const url = URL.createObjectURL(blob);
			const a = document.createElement("a");
			const dateStr = new Date().toISOString().slice(0, 10);
			a.href = url;
			a.download = `lanforge-config-${dateStr}.json`;
			document.body.appendChild(a);
			a.click();
			document.body.removeChild(a);
			URL.revokeObjectURL(url);
			toast.success("Configuration exported successfully", {
				description: "Saved aggregated JSON persistence snapshot.",
			});
		} catch (e: any) {
			toast.error("Export failed", {
				description: e?.message || "Internal server error",
			});
		} finally {
			exporting = false;
		}
	}

	async function handleExportToml() {
		exportingToml = true;
		try {
			const tomlStr = await exportSystemConfigToml();
			const blob = new Blob([tomlStr], { type: "text/plain;charset=utf-8" });
			const url = URL.createObjectURL(blob);
			const a = document.createElement("a");
			const dateStr = new Date().toISOString().slice(0, 10);
			a.href = url;
			a.download = `lanforge-${dateStr}.toml`;
			document.body.appendChild(a);
			a.click();
			document.body.removeChild(a);
			URL.revokeObjectURL(url);
			toast.success("TOML configuration exported", {
				description: "Saved consolidated lanforge.toml file.",
			});
		} catch (e: any) {
			toast.error("Export failed", {
				description: e?.message || "Internal server error",
			});
		} finally {
			exportingToml = false;
		}
	}

	function handleFileSelected(event: Event) {
		const target = event.target as HTMLInputElement;
		if (target.files && target.files.length > 0) {
			selectedFile = target.files[0];
		}
	}

	async function handleImport() {
		if (!selectedFile) {
			toast.error("Please select a JSON configuration file to import.");
			return;
		}

		importing = true;
		try {
			const text = await selectedFile.text();
			let parsed: SystemConfigExport;
			try {
				parsed = JSON.parse(text);
			} catch {
				toast.error("Invalid JSON file", {
					description: "The selected file is not a valid JSON document.",
				});
				importing = false;
				return;
			}

			parsed.overwrite = importOverwrite;

			const resp = await importSystemConfig(parsed);
			importResult = resp;
			showImportResultDialog = true;

			if (resp.total_success) {
				toast.success("Configuration imported successfully");
			} else {
				toast.warning("Configuration import finished with some warnings");
			}

			selectedFile = null;
			if (importFileInput) importFileInput.value = "";
			await dbState.loadAll(true);
		} catch (e: any) {
			toast.error("Import failed", {
				description: e?.message || "Internal server error",
			});
		} finally {
			importing = false;
		}
	}
</script>

<DbBackupTab
	{exporting}
	{exportingToml}
	{importing}
	{selectedFile}
	bind:importOverwrite
	bind:importFileInput
	{formatBytes}
	onExportToml={handleExportToml}
	onExportJson={handleExport}
	onFileSelected={handleFileSelected}
	onImport={handleImport}
/>

<!-- Import Results Dialog -->
<DbImportResultModal
	bind:open={showImportResultDialog}
	result={importResult}
/>
