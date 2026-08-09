// Import the employee data from data.ts
import { users } from "./data";


// This function checks our first security control:
//
// AC-001:
// "Every active admin must have MFA enabled."
//
// "export" means other files can use this function.
export function checkPrivilegedMFA() {

	// .filter() goes through every user
	// and keeps only the users who violate the rule.
	const failures = users.filter(
		(user) =>
			user.active &&
			user.role === "admin" &&
			!user.mfa
	);

	// Return a structured result describing
	// whether the control passed or failed.
	return {
		controlId: "AC-001",
		controlName: "Privileged accounts require MFA",

		// If nobody failed, the control passes.
		// If at least one person failed, it fails.
		status: failures.length === 0 ? "PASS" : "FAIL",

		// Include the users who violated the control.
		failures: failures,
	};
}