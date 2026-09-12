<script lang="ts">
	import { toast } from "svelte-sonner";
	import { switchDbEngine } from "$lib/api/client";
	import type { DbEngineSwitchRequest } from "$lib/api/types";
	import DbSettingsTab from "../components/DbSettingsTab.svelte";
	import { dbState } from "../dbState.svelte";

	let formStorageType = $state<"persistent" | "volatile">("persistent");
	let formUrl = $state("/var/lib/lanforge/lanforge.redb");
	let formFlushInterval = $state(60);
	let formLogUrl = $state("/run/lanforge/runtime.redb");
	let applyingEngineSwitch = $state(false);

	let baselineForm = $state<string | null>(null);

	function serializeForm(): string {
		return JSON.stringify({
			storageType: formStorageType,
			url: formUrl.trim(),
			flush: Number(formFlushInterval),
			logUrl: formLogUrl.trim(),
		});
	}

	function syncFormFromStatus() {
		const rawPath = dbState.systemStatus?.db?.path || "";
		if (dbState.isInMemory || rawPath.startsWith("/tmp") || rawPath.startsWith("/run")) {
			formStorageType = "volatile";
			formUrl = rawPath || "/run/lanforge/config.redb";
		} else {
			formStorageType = "persistent";
			formUrl = rawPath || "/var/lib/lanforge/config.redb";
		}
		formFlushInterval = 60;
		formLogUrl = "/run/lanforge/runtime.redb";

		baselineForm = serializeForm();
	}

	$effect(() => {
		if (dbState.systemStatus && !baselineForm) {
			syncFormFromStatus();
		}
	});

	const isDirty = $derived.by(() => {
		if (!baselineForm) return false;
		return serializeForm() !== baselineForm;
	});

	const computedToml = $derived.by(() => {
		if (formStorageType === "volatile") {
			return `[database]
config_path = "memory"
runtime_path = "memory"`;
		}
		const urlVal = formUrl.trim() || "/var/lib/lanforge/config.redb";
		return `[database]
config_path = "${urlVal}"
runtime_path = "${formLogUrl || "/run/lanforge/runtime.redb"}"
flush_interval = ${formFlushInterval || 60}`;
	});

	function copyTomlSample() {
		navigator.clipboard.writeText(computedToml);
		toast.success("Configuration copied to clipboard", {
			description: "Paste into your /etc/lanforge/lanforge.toml file.",
		});
	}

	function handleDiscardForm() {
		syncFormFromStatus();
		toast.info("Settings reverted to active daemon parameters");
	}

	async function handleApplyEngineSwitch() {
		applyingEngineSwitch = true;
		try {
			const targetUrl =
				formUrl.trim() ||
				(formStorageType === "persistent"
					? "/var/lib/lanforge/lanforge.redb"
					: "/run/lanforge/lanforge.redb");

			const payload: DbEngineSwitchRequest = {
				engine: "redb",
				url: targetUrl,
			};

			await switchDbEngine(payload);

			toast.success("Storage configuration updated. Soft-rebooting daemon...", {
				description: "The daemon is soft-rebooting internal services with the new storage configuration.",
				duration: 6000,
			});

			baselineForm = serializeForm();

			setTimeout(() => {
				dbState.loadAll(true);
			}, 2500);
		} catch (e: any) {
			toast.error("Failed to update storage configuration", {
				description: e?.message || "Internal server error",
			});
		} finally {
			applyingEngineSwitch = false;
		}
	}
</script>

<DbSettingsTab
	bind:formStorageType
	bind:formUrl
	bind:formFlushInterval
	bind:formLogUrl
	{computedToml}
	{isDirty}
	{applyingEngineSwitch}
	onDiscard={handleDiscardForm}
	onApply={handleApplyEngineSwitch}
	onCopyToml={copyTomlSample}
/>
