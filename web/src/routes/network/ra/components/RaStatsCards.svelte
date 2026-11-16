<script lang="ts">
	import NetworkIcon from "@lucide/svelte/icons/network";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import ClockIcon from "@lucide/svelte/icons/clock";
	import RadioIcon from "@lucide/svelte/icons/radio";
	import StatStrip from "$lib/components/StatStrip.svelte";
	import type { RaStatusResponse } from "$lib/api/types";

	let {
		status = null,
	}: {
		status?: RaStatusResponse | null;
	} = $props();

	function formatSeconds(sec: number | null | undefined): string {
		if (sec === null || sec === undefined) return "Never";
		if (sec < 60) return `${sec}s ago`;
		if (sec < 3600) return `${Math.floor(sec / 60)}m ${sec % 60}s ago`;
		const h = Math.floor(sec / 3600);
		const m = Math.floor((sec % 3600) / 60);
		return `${h}h ${m}m ago`;
	}

	function formatCountdown(sec: number | null | undefined): string {
		if (sec === null || sec === undefined) return "—";
		if (sec === 0) return "Imminent";
		if (sec < 60) return `in ${sec}s`;
		const m = Math.floor(sec / 60);
		const s = sec % 60;
		return `in ${m}m ${s}s`;
	}
</script>

<StatStrip
	items={[
		{
			label: status?.enabled ? "interface" : "interface (not sending)",
			value: status?.interface ?? "Not bound",
			icon: NetworkIcon,
		},
		{
			label: `RAs sent (${status?.sent_multicast_ras ?? 0} timed, ${status?.sent_unicast_ras ?? 0} replies)`,
			value: (status?.sent_multicast_ras ?? 0) + (status?.sent_unicast_ras ?? 0),
			icon: ActivityIcon,
		},
		{
			label: `requests from devices, last ${formatSeconds(status?.last_rs_received_secs_ago)}`,
			value: status?.received_solicitations ?? 0,
			icon: RadioIcon,
		},
		{
			label: `next RA, last sent ${formatSeconds(status?.last_ra_sent_secs_ago)}`,
			value: formatCountdown(status?.next_ra_in_secs),
			icon: ClockIcon,
		},
	]}
/>
