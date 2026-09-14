<script lang="ts">
	import { onMount } from "svelte";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import SaveIcon from "@lucide/svelte/icons/save";
	import RotateCcwIcon from "@lucide/svelte/icons/rotate-ccw";
	import { toast } from "svelte-sonner";
	import HelpPopover from "$lib/components/HelpPopover.svelte";

	import TftpVitalsCards from "./components/TftpVitalsCards.svelte";
	import TftpServerCard from "./components/TftpServerCard.svelte";
	import TftpNetbootCard from "./components/TftpNetbootCard.svelte";

	import {
		dhcpOptionsGet,
		dhcpOptionsUpdate,
		status as getSystemStatus,
		serviceBanners,
		controlService,
	} from "$lib/api/client";
	import type {
		DhcpOptionsConfig,
		TftpOptions,
		StatusResponse,
		ServiceBanner,
	} from "$lib/api/types";

	let loading = $state(true);
	let saving = $state(false);
	let serviceActionLoading = $state<string | null>(null);

	let fullOptions = $state<DhcpOptionsConfig | null>(null);
	let systemStatus = $state<StatusResponse | null>(null);
	let tftpBanner = $state<ServiceBanner | null>(null);

	// TFTP Server form fields
	let enabled = $state(false);
	let listenAddr = $state("0.0.0.0:69");
	let rootDir = $state("/var/lib/lanforge/tftp");
	let blockSize = $state(512);
	let timeoutSecs = $state(5);
	let maxRetries = $state(3);

	// DHCP PXE Integration fields
	let dhcpV4TftpServer = $state("");
	let dhcpV4BootFile = $state("");
	let dhcpV6BootFile = $state("");

	let pristineTftpJson = $state("");
	let pristineDhcpPxeJson = $state("");

	function currentTftpPayload(): TftpOptions {
		return {
			enabled,
			listen_addr: listenAddr.trim() || "0.0.0.0:69",
			root_dir: rootDir.trim() || "/var/lib/lanforge/tftp",
			block_size: Number(blockSize) || 512,
			timeout: Number(timeoutSecs) || 5,
			max_retries: Number(maxRetries) || 3,
		};
	}

	function currentDhcpPxePayload() {
		return {
			tftp_server: dhcpV4TftpServer.trim() || null,
			v4_boot_file: dhcpV4BootFile.trim() || null,
			v6_boot_file: dhcpV6BootFile.trim() || null,
		};
	}

	const isDirty = $derived.by(() => {
		if (loading) return false;
		const tftpChanged = JSON.stringify(currentTftpPayload()) !== pristineTftpJson;
		const dhcpChanged = JSON.stringify(currentDhcpPxePayload()) !== pristineDhcpPxeJson;
		return tftpChanged || dhcpChanged;
	});

	async function loadAllData() {
		loading = true;
		try {
			const [optsRes, sysRes, bannersRes] = await Promise.allSettled([
				dhcpOptionsGet(),
				getSystemStatus(),
				serviceBanners(),
			]);

			if (optsRes.status === "fulfilled") {
				fullOptions = optsRes.value;
				const tftp = optsRes.value.tftp ?? {
					enabled: false,
					listen_addr: "0.0.0.0:69",
					root_dir: "/var/lib/lanforge/tftp",
					block_size: 512,
					timeout: 5,
					max_retries: 3,
				};

				enabled = tftp.enabled ?? false;
				listenAddr = tftp.listen_addr || "0.0.0.0:69";
				rootDir = tftp.root_dir || "/var/lib/lanforge/tftp";
				blockSize = tftp.block_size || 512;
				timeoutSecs = tftp.timeout || 5;
				maxRetries = tftp.max_retries || 3;

				dhcpV4TftpServer = optsRes.value.v4?.tftp_server || "";
				dhcpV4BootFile = optsRes.value.v4?.boot_file || "";
				dhcpV6BootFile = optsRes.value.v6?.boot_file || "";

				pristineTftpJson = JSON.stringify(currentTftpPayload());
				pristineDhcpPxeJson = JSON.stringify(currentDhcpPxePayload());
			}

			if (sysRes.status === "fulfilled") {
				systemStatus = sysRes.value;
			}

			if (bannersRes.status === "fulfilled") {
				const list = bannersRes.value;
				tftpBanner = list.find(
					(b) => b.id?.toLowerCase() === "tftp" || b.name.toLowerCase().includes("tftp"),
				) ?? null;
			}
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : "Erro ao carregar dados do TFTP.";
			toast.error(`Falha ao carregar configurações do TFTP: ${msg}`);
		} finally {
			loading = false;
		}
	}

	function resetForm() {
		if (!pristineTftpJson) return;
		const origTftp: TftpOptions = JSON.parse(pristineTftpJson);
		enabled = origTftp.enabled ?? false;
		listenAddr = origTftp.listen_addr ?? "0.0.0.0:69";
		rootDir = origTftp.root_dir ?? "/var/lib/lanforge/tftp";
		blockSize = origTftp.block_size ?? 512;
		timeoutSecs = origTftp.timeout ?? 5;
		maxRetries = origTftp.max_retries ?? 3;

		if (pristineDhcpPxeJson) {
			const origDhcp = JSON.parse(pristineDhcpPxeJson);
			dhcpV4TftpServer = origDhcp.tftp_server || "";
			dhcpV4BootFile = origDhcp.v4_boot_file || "";
			dhcpV6BootFile = origDhcp.v6_boot_file || "";
		}
		toast.info("Formulário redefinido para a configuração salva");
	}

	async function saveAll() {
		if (!fullOptions) return;
		saving = true;
		try {
			const tftp = currentTftpPayload();
			const dhcp = currentDhcpPxePayload();

			const mergedPayload: DhcpOptionsConfig = {
				...fullOptions,
				tftp,
				v4: {
					...fullOptions.v4,
					tftp_server: dhcp.tftp_server,
					boot_file: dhcp.v4_boot_file,
				},
				v6: {
					...fullOptions.v6,
					boot_file: dhcp.v6_boot_file,
				},
			};

			await dhcpOptionsUpdate(mergedPayload);
			fullOptions = mergedPayload;
			pristineTftpJson = JSON.stringify(tftp);
			pristineDhcpPxeJson = JSON.stringify(dhcp);

			toast.success("Configurações do servidor TFTP e PXE salvas com sucesso");

			// Refresh banners to sync state
			setTimeout(async () => {
				try {
					const banners = await serviceBanners();
					tftpBanner = banners.find(
						(b) => b.id?.toLowerCase() === "tftp" || b.name.toLowerCase().includes("tftp"),
					) ?? null;
				} catch {
					// non-critical
				}
			}, 750);
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : "Erro desconhecido";
			toast.error(`Falha ao salvar configurações do TFTP: ${msg}`);
		} finally {
			saving = false;
		}
	}

	async function handleServiceControl(action: "Start" | "Stop" | "Restart") {
		serviceActionLoading = action;
		try {
			await controlService("tftp", action);
			toast.success(`Serviço TFTP recebeu comando ${action.toLowerCase()}`);
			setTimeout(async () => {
				const banners = await serviceBanners();
				tftpBanner = banners.find(
					(b) => b.id?.toLowerCase() === "tftp" || b.name.toLowerCase().includes("tftp"),
				) ?? null;
				serviceActionLoading = null;
			}, 750);
		} catch (err: unknown) {
			serviceActionLoading = null;
			const msg = err instanceof Error ? err.message : "Erro desconhecido";
			toast.error(`Falha ao executar ${action.toLowerCase()} no serviço TFTP: ${msg}`);
		}
	}

	function useLanforgeIp() {
		const ip = systemStatus?.network?.lan_ipv4;
		if (ip) {
			dhcpV4TftpServer = ip;
			toast.success(`Opção 66 configurada com o IP do Lanforge: ${ip}`);
		} else {
			toast.error("Endereço IPv4 LAN do Lanforge indisponível no status");
		}
	}

	onMount(loadAllData);

	const serviceState = $derived(tftpBanner?.state?.toLowerCase() ?? (enabled ? "active" : "inactive"));
	const isServiceActive = $derived(serviceState === "active" || serviceState === "online");
</script>

<svelte:head>
	<title>TFTP Server & Netboot — Lanforge</title>
</svelte:head>

<div class="flex flex-col gap-6">
	<!-- Page Header -->
	<div class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
		<div>
			<div class="flex items-center gap-2.5">
				<h1 class="text-foreground text-2xl font-bold tracking-tight">
					TFTP Server & Netboot
				</h1>
				<Badge
					variant={isServiceActive ? "default" : "secondary"}
					class="font-mono text-[10px] uppercase tracking-wider"
				>
					{serviceState}
				</Badge>
				<HelpPopover
					title="TFTP Netboot Setup"
					description="Servidor TFTP (Trivial File Transfer Protocol) para boot de rede PXE/UEFI e instalação automatizada de sistemas operacionais."
				>
					{#snippet children()}
						<div class="flex flex-col gap-2.5 text-xs text-muted-foreground">
							<div class="flex flex-col gap-0.5 border-l-2 border-primary/50 pl-2">
								<span class="font-semibold text-foreground">1. Diretório Raiz</span>
								<span>Copie kernels ou bootloaders (ex: <code class="text-foreground">ipxe.efi</code>) para <code class="text-foreground">{rootDir}</code>.</span>
							</div>
							<div class="flex flex-col gap-0.5 border-l-2 border-primary/50 pl-2">
								<span class="font-semibold text-foreground">2. Daemon Ativo</span>
								<span>Habilite o servidor TFTP. Certifique-se de que a porta UDP 69 esteja acessível.</span>
							</div>
							<div class="flex flex-col gap-0.5 border-l-2 border-primary/50 pl-2">
								<span class="font-semibold text-foreground">3. Opções DHCP 66 & 67</span>
								<span>A Opção 66 aponta para o IP do Lanforge e a Opção 67 especifica o executável NBP.</span>
							</div>
							<div class="flex flex-col gap-0.5 border-l-2 border-primary/50 pl-2">
								<span class="font-semibold text-foreground">4. Boot dos Clientes PXE</span>
								<span>Os clientes BIOS/UEFI configurados para inicialização via rede carregarão o bootloader automaticamente.</span>
							</div>
						</div>
					{/snippet}
				</HelpPopover>
			</div>
			<p class="text-muted-foreground text-sm mt-0.5">
				Servidor de arquivos TFTP para boot de rede PXE e provisionamento de sistemas operacionais
			</p>
		</div>

		<!-- Action Bar -->
		<div class="flex items-center gap-2">
			<Button
				variant="outline"
				size="sm"
				class="cursor-pointer"
				onclick={loadAllData}
				disabled={loading}
			>
				<RefreshCwIcon
					data-icon="inline-start"
					class={loading ? "animate-spin" : ""}
				/>
				Atualizar
			</Button>

			{#if isDirty}
				<Button
					variant="ghost"
					size="sm"
					class="cursor-pointer"
					onclick={resetForm}
					disabled={saving}
				>
					<RotateCcwIcon data-icon="inline-start" />
					Descartar
				</Button>
				<Button
					size="sm"
					class="cursor-pointer"
					onclick={saveAll}
					disabled={saving}
				>
					<SaveIcon
						data-icon="inline-start"
						class={saving ? "animate-spin" : ""}
					/>
					Salvar Alterações
				</Button>
			{/if}
		</div>
	</div>

	<!-- Vitals / Stat Cards -->
	<TftpVitalsCards
		{loading}
		{isServiceActive}
		{serviceState}
		{enabled}
		{listenAddr}
		{rootDir}
		{blockSize}
		{timeoutSecs}
		{maxRetries}
		{serviceActionLoading}
		onServiceControl={handleServiceControl}
	/>

	<!-- Main Workspace Grid: TFTP Server Config (Col 1) + DHCP PXE Integration (Col 2) -->
	<div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
		<TftpServerCard
			{loading}
			bind:enabled
			bind:rootDir
			bind:listenAddr
			bind:blockSize
			bind:timeoutSecs
			bind:maxRetries
		/>

		<TftpNetbootCard
			{loading}
			bind:dhcpV4TftpServer
			bind:dhcpV4BootFile
			bind:dhcpV6BootFile
			lanIpv4={systemStatus?.network?.lan_ipv4}
			onUseLanforgeIp={useLanforgeIp}
		/>
	</div>
</div>
