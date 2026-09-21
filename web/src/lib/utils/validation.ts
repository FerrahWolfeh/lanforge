import { z, type ZodSchema } from 'zod';

export type FieldErrors<T> = Partial<Record<keyof T, string>>;

/**
 * Validate data against a Zod schema and return a flat record of field errors
 * for immediate visual feedback in shadcn-svelte form fields.
 */
export function validateForm<T>(
	schema: ZodSchema<T>,
	data: unknown
): { success: true; data: T } | { success: false; errors: FieldErrors<T> } {
	const result = schema.safeParse(data);
	if (result.success) {
		return { success: true, data: result.data };
	}

	const errors: FieldErrors<T> = {};
	for (const issue of result.error.issues) {
		const field = issue.path[0] as keyof T;
		if (field && !errors[field]) {
			errors[field] = issue.message;
		}
	}

	return { success: false, errors };
}

// ---------------------------------------------------------------------------
// Common Network Validation Schemas (Strict, English error messages)
// ---------------------------------------------------------------------------

export const macAddressRegex = /^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$/;

export const macSchema = z
	.string()
	.trim()
	.regex(macAddressRegex, 'Invalid MAC address format (e.g. aa:bb:cc:dd:ee:ff)');

export const ipv4Schema = z
	.string()
	.trim()
	.ipv4('Invalid IPv4 address format (e.g. 192.168.1.100)');

export const ipv6Schema = z
	.string()
	.trim()
	.ipv6('Invalid IPv6 address format (e.g. 2001:db8::1)');

export const portNumberSchema = z.coerce
	.number('Port must be a valid number')
	.int('Port must be an integer')
	.min(1, 'Port must be between 1 and 65535')
	.max(65535, 'Port must be between 1 and 65535');

export const hostnameSchema = z
	.string()
	.trim()
	.min(1, 'Hostname cannot be empty')
	.max(63, 'Hostname cannot exceed 63 characters')
	.regex(/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/, 'Hostname may only contain alphanumeric characters and hyphens');
