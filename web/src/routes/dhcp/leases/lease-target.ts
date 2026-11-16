import type { LeaseEntry, LeaseTarget } from "$lib/api/types";

/** The daemon matches DHCPv6 leases by IAID, so a v6 lease without one cannot be targeted. */
export function leaseTarget(lease: LeaseEntry): LeaseTarget {
	if (lease.kind === "v4") return "V4";
	if (lease.iaid == null) throw new Error("This lease has no IAID; reload the list and try again");
	return lease.kind === "v6_prefix"
		? { V6Prefix: { iaid: lease.iaid } }
		: { V6: { iaid: lease.iaid } };
}
