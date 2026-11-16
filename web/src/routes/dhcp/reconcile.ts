import { toast } from "svelte-sonner";
import type { DhcpReconcileResponse } from "$lib/api/types";

/** Reports what a lease reconcile did: all in range, or which leases were invalidated. */
export function toastReconcileResult(res: DhcpReconcileResponse) {
	if (res.invalidated_v4_leases.length === 0) {
		toast.success(
			`DHCP Reconcile: All leases within range (${res.valid_v4_leases} active, ${res.preserved_static_leases} static preserved)`,
		);
		return;
	}
	toast.warning(
		`Reconcile: Invalidated ${res.invalidated_v4_leases.length} out-of-range lease(s). ForceRenew sent.`,
		{
			description:
				res.invalidated_v4_leases
					.map((l) => `${l.mac} (${l.ip})`)
					.slice(0, 3)
					.join(", ") + (res.invalidated_v4_leases.length > 3 ? "..." : ""),
			duration: 8000,
		},
	);
}
