<script lang="ts">
	import { downloadBlob } from "$lib/utils";
	import { toast } from "svelte-sonner";
	import {
		exportSystemConfig,
		exportSystemConfigToml,
		importSystemConfig,
	} from "$lib/api/client";
	import * as AlertDialog from "$lib/components/ui/alert-dialog";
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
	let confirmOverwriteOpen = $state(false);

	async function handleExport() {
		exporting = true;
		try {
			const config = await exportSystemConfig();
			const dateStr = new Date().toISOString().slice(0, 10);
			downloadBlob(JSON.stringify(config, null, 2), `lanforge-config-${dateStr}.json`, "application/json");
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
			const dateStr = new Date().toISOString().slice(0, 10);
			downloadBlob(tomlStr, `lanforge-${dateStr}.toml`, "text/plain;charset=utf-8");
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

	function requestImport() {
		if (importOverwrite && selectedFile) confirmOverwriteOpen = true;
		else handleImport();
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
	onImport={requestImport}
/>

<!-- Import Results Dialog -->
<DbImportResultModal
	bind:open={showImportResultDialog}
	result={importResult}
/>

<AlertDialog.Root bind:open={confirmOverwriteOpen}>
	<AlertDialog.Content class="rounded-lg">
		<AlertDialog.Header>
			<AlertDialog.Title class="text-base font-bold text-foreground">
				Overwrite existing records?
			</AlertDialog.Title>
			<AlertDialog.Description class="text-xs">
				Importing with "Overwrite Existing Records" replaces the current records with the contents of the file. This cannot be undone.
			</AlertDialog.Description>
		</AlertDialog.Header>
		<AlertDialog.Footer>
			<AlertDialog.Cancel class="cursor-pointer text-xs">Cancel</AlertDialog.Cancel>
			<AlertDialog.Action
				class="cursor-pointer text-xs bg-destructive text-destructive-foreground hover:bg-destructive/90"
				onclick={handleImport}
			>
				Import and Overwrite
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
