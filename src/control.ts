import { users } from "./data";


// AC-001: Active privileged accounts must have MFA enabled.
export function checkPrivilegedMFA() {

	const failures = users.filter(
		(user) =>
			user.active &&
			user.role === "admin" &&
			!user.mfa
	);

	return {
		controlId: "AC-001",
		controlName: "Privileged accounts require MFA",
		status: failures.length === 0 ? "PASS" : "FAIL",
		failures,
	};
}


// AC-002: Terminated employees must not retain active accounts.
export function checkTerminatedAccounts() {

	const failures = users.filter(
		(user) =>
			user.employmentStatus === "terminated" &&
			user.active
	);

	return {
		controlId: "AC-002",
		controlName:
			"Terminated employees must not retain active accounts",
		status: failures.length === 0 ? "PASS" : "FAIL",
		failures,
	};
}


// AC-003: Active privileged accounts must have completed
// an access review within the last 90 days.
export function checkPrivilegedAccessReviews() {

	const now = new Date();

	const ninetyDays =
		90 * 24 * 60 * 60 * 1000;


	const failures = users.filter((user) => {

		// AC-003 only applies to active admins.
		if (
			!user.active ||
			user.role !== "admin"
		) {
			return false;
		}


		const lastReview =
			new Date(
				user.lastAccessReview
			);


		const reviewAge =
			now.getTime() -
			lastReview.getTime();


		return reviewAge > ninetyDays;
	});


	return {
		controlId: "AC-003",
		controlName:
			"Privileged accounts require access review within 90 days",
		status:
			failures.length === 0
				? "PASS"
				: "FAIL",
		failures,
	};
}