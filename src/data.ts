// Synthetic identity data used by the control engine.

export const users = [

	{
		id: 1,
		name: "Alice",
		role: "admin",
		mfa: true,
		active: true,
		employmentStatus: "active",

		// Most recent privileged access review.
		lastAccessReview: "2026-07-15",
	},

	{
		id: 2,
		name: "Bob",
		role: "admin",
		mfa: false,
		active: true,
		employmentStatus: "active",

		// Intentionally stale review for AC-003 testing.
		lastAccessReview: "2026-04-01",
	},

	{
		id: 3,
		name: "Carol",
		role: "employee",
		mfa: false,
		active: true,
		employmentStatus: "active",

		lastAccessReview: "2026-07-20",
	},

	{
		id: 4,
		name: "Dave",
		role: "employee",
		mfa: true,

		// Terminated user whose account was not deprovisioned.
		active: true,
		employmentStatus: "terminated",

		lastAccessReview: "2026-05-01",
	},

];