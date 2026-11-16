import { toast } from "svelte-sonner";
import { dnsAllow, dnsBlock } from "$lib/api/client";
import type { AdblockSourceMatch, DnsRecordType, FilterMatch, FilterOrigin } from "$lib/api/types";

export const RECORD_TYPES: DnsRecordType[] = [
	"A",
	"AAAA",
	"CNAME",
	"PTR",
	"TXT",
	"MX",
	"NS",
	"SOA",
	"SRV",
	"HTTPS",
	"SVCB",
];

export function cleanDomain(raw: string): string {
	if (!raw) return "";
	return raw.trim().replace(/\.$/, "");
}

export function cleanAnswer(raw?: string | null): string {
	if (!raw) return "—";
	return raw
		.replace(/^"|"$/g, "")
		.replace(/^(A|AAAA|CNAME|PTR|NS)\((.*)\)$/, "$2")
		.trim()
		.replace(/\.$/, "");
}

/** Where a filter match came from, in words. A list is named by its URL when `sourceMatches` has it. */
export function originText(origin: FilterOrigin, sourceMatches: AdblockSourceMatch[] = []): string {
	switch (origin.type) {
		case "user_rule":
			return "your own block rules";
		case "user_allowlist":
			return "your own allow rules";
		case "group_rule":
			return `the block rules of the group "${origin.group}"`;
		case "group_allowlist":
			return `the allow rules of the group "${origin.group}"`;
		case "list":
		case "group_list": {
			const url = sourceMatches.find((m) => m.source_id === origin.source_id)?.url;
			const where = url ? `the list ${url}` : `adblock list #${origin.source_id}`;
			return origin.type === "group_list" ? `${where} (group "${origin.group}")` : where;
		}
	}
}

/** Adds a domain to the adblock black list or allowlist from a quick action; toasts the outcome. */
export async function quickDnsRule(action: "block" | "allow", domain: string): Promise<boolean> {
	const target = cleanDomain(domain);
	try {
		if (action === "block") {
			await dnsBlock(target);
			toast.success(`Added ${target} to adblock black list`);
		} else {
			await dnsAllow(target);
			toast.success(`Added ${target} to allowlist`);
		}
		return true;
	} catch (err: any) {
		toast.error(err?.message ?? `Failed to ${action} domain`);
		return false;
	}
}

export function getResultBadge(result: string, cached: boolean, filter?: FilterMatch | null) {
	if (filter?.action === "allow") {
		return {
			label: "Allowed (@@)",
			class: "bg-success/10 text-success border-success/20",
		};
	}
	const lower = (result || "").toLowerCase();
	if (
		lower === "cachedblock" ||
		lower === "cached_block" ||
		(lower.includes("block") && cached)
	) {
		return {
			label: "Cached Block",
			class: "bg-warning/10 text-warning border-warning/20",
		};
	}
	if (lower.includes("block") || lower.includes("deny")) {
		return {
			label: "Blocked",
			class: "bg-danger/10 text-danger border-danger/20",
		};
	}
	if (lower === "rewritten" || lower.includes("rewrite")) {
		return {
			label: "Rewritten",
			class: "bg-selected text-selected-foreground border-transparent",
		};
	}
	if (lower === "local") {
		return {
			label: "Local",
			class: "bg-muted text-muted-foreground border-border",
		};
	}
	if (lower === "nxdomain") {
		return {
			label: "NXDomain",
			class: "bg-warning/10 text-warning border-warning/20",
		};
	}
	if (lower === "error") {
		return {
			label: "Error",
			class: "bg-danger/10 text-danger border-danger/20",
		};
	}
	if (cached || lower === "cached") {
		return {
			label: "Cached",
			class: "bg-success/10 text-success border-success/20",
		};
	}
	if (lower === "coalesced") {
		return {
			label: "Coalesced",
			class: "bg-info/10 text-info border-info/20",
		};
	}
	return {
		label: "Forwarded",
		class: "bg-muted text-muted-foreground border-border",
	};
}
