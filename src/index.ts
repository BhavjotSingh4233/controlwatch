import { users } from "./data";
import { checkPrivilegedMFA } from "./control";

// This tells TypeScript that our Worker has access to:
// 1. A D1 database
// 2. An R2 evidence bucket
interface Env {
	controlwatch_db: D1Database;
	controlwatch_evidence: R2Bucket;
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {

		// Turn the incoming request into a URL object
		// so we can inspect which path was requested.
		const url = new URL(request.url);


		// ---------------------------------------------------------
		// ROUTE 1: HOME
		// ---------------------------------------------------------

		if (url.pathname === "/") {
			return Response.json({
				name: "ControlWatch",
				description: "Automated GRC control monitoring",
			});
		}


		// ---------------------------------------------------------
		// ROUTE 2: SHOW USERS
		// ---------------------------------------------------------

		if (url.pathname === "/api/users") {
			return Response.json(users);
		}


		// ---------------------------------------------------------
		// ROUTE 3: RUN CONTROL AC-001
		// ---------------------------------------------------------

		if (url.pathname === "/api/assess/AC-001") {

			// Run our security control.
			//
			// This checks whether every active admin
			// has MFA enabled.
			const result = checkPrivilegedMFA();


			// Record the exact time this assessment ran.
			const assessedAt = new Date().toISOString();


			// -----------------------------------------------------
			// STEP 1: SAVE THE ASSESSMENT INTO D1
			// -----------------------------------------------------

			// At this point, we do NOT know the evidence key yet,
			// because the evidence file name will include the
			// assessment ID that D1 gives us.
			const assessmentInsert = await env.controlwatch_db
				.prepare(`
					INSERT INTO assessments (
						control_id,
						status,
						assessed_at
					)
					VALUES (?, ?, ?)
				`)
				.bind(
					result.controlId,
					result.status,
					assessedAt
				)
				.run();


			// Get the ID of the assessment row
			// that was just created.
			const assessmentId =
				assessmentInsert.meta.last_row_id;


			// -----------------------------------------------------
			// STEP 2: CREATE THE R2 EVIDENCE KEY
			// -----------------------------------------------------

			// Create a unique file path for this assessment.
			//
			// Example:
			// AC-001/assessment-6.json
			const evidenceKey =
				`${result.controlId}/assessment-${assessmentId}.json`;


			// -----------------------------------------------------
			// STEP 3: BUILD THE RAW EVIDENCE OBJECT
			// -----------------------------------------------------

			// This is the exact data our control evaluated.
			const evidence = {
				controlId: result.controlId,
				controlName: result.controlName,
				assessmentId: assessmentId,
				assessedAt: assessedAt,
				source: "synthetic-identity-data",
				users: users,
			};


			// Convert the JavaScript object into JSON text.
			const evidenceJson =
				JSON.stringify(evidence, null, 2);


			// -----------------------------------------------------
			// STEP 4: SAVE RAW EVIDENCE INTO R2
			// -----------------------------------------------------

			await env.controlwatch_evidence.put(
				evidenceKey,
				evidenceJson,
				{
					httpMetadata: {
						contentType: "application/json",
					},
				}
			);


			// -----------------------------------------------------
			// STEP 5: LINK R2 EVIDENCE BACK TO D1
			// -----------------------------------------------------

			// Now that we know the evidence key,
			// update the assessment row so it points
			// directly to the supporting R2 evidence file.
			await env.controlwatch_db
				.prepare(`
					UPDATE assessments
					SET evidence_key = ?
					WHERE id = ?
				`)
				.bind(
					evidenceKey,
					assessmentId
				)
				.run();


			// -----------------------------------------------------
			// STEP 6: CREATE FINDINGS FOR FAILED USERS
			// -----------------------------------------------------

			// result.failures contains every user
			// who violated AC-001.
			for (const failure of result.failures) {

				await env.controlwatch_db
					.prepare(`
						INSERT INTO findings (
							assessment_id,
							control_id,
							severity,
							subject,
							description,
							status
						)
						VALUES (?, ?, ?, ?, ?, ?)
					`)
					.bind(
						// Link this finding to the assessment.
						assessmentId,

						// Which control failed.
						result.controlId,

						// Demo severity.
						"HIGH",

						// Person who caused the failure.
						failure.name,

						// Human-readable description.
						"Active privileged account does not have MFA enabled",

						// Finding has not been resolved yet.
						"OPEN"
					)
					.run();
			}


			// -----------------------------------------------------
			// STEP 7: RETURN THE ASSESSMENT RESULT
			// -----------------------------------------------------

			return Response.json({
				...result,
				assessmentId: assessmentId,
				assessedAt: assessedAt,
				evidenceKey: evidenceKey,
				savedToDatabase: true,
				savedEvidenceToR2: true,
				evidenceLinkedToAssessment: true,
			});
		}


		// ---------------------------------------------------------
		// ROUTE 4: GET ALL FINDINGS
		// ---------------------------------------------------------

		if (url.pathname === "/api/findings") {

			const query = await env.controlwatch_db
				.prepare(`
					SELECT *
					FROM findings
					ORDER BY id DESC
				`)
				.all();

			return Response.json(query.results);
		}


		// ---------------------------------------------------------
		// ROUTE 5: GET ALL ASSESSMENTS
		// ---------------------------------------------------------

		if (url.pathname === "/api/assessments") {

			// Read the full assessment history from D1.
			const query = await env.controlwatch_db
				.prepare(`
					SELECT *
					FROM assessments
					ORDER BY id DESC
				`)
				.all();

			return Response.json(query.results);
		}


		// ---------------------------------------------------------
		// ROUTE 6: GET EVIDENCE FROM R2
		// ---------------------------------------------------------

		// Example:
		//
		// /api/evidence/AC-001/assessment-6.json
		if (url.pathname.startsWith("/api/evidence/")) {

			// Remove "/api/evidence/" from the URL.
			//
			// Example:
			//
			// /api/evidence/AC-001/assessment-6.json
			//
			// becomes:
			//
			// AC-001/assessment-6.json
			const evidenceKey = url.pathname.replace(
				"/api/evidence/",
				""
			);


			// Ask R2 for that evidence file.
			const object =
				await env.controlwatch_evidence.get(
					evidenceKey
				);


			// If it doesn't exist, return 404.
			if (object === null) {
				return Response.json(
					{
						error: "Evidence not found",
					},
					{
						status: 404,
					}
				);
			}


			// Read the evidence file as text.
			const evidenceText =
				await object.text();


			// Return the evidence JSON to the browser.
			return new Response(
				evidenceText,
				{
					headers: {
						"Content-Type": "application/json",
					},
				}
			);
		}


		// ---------------------------------------------------------
		// ROUTE 7: NOT FOUND
		// ---------------------------------------------------------

		return Response.json(
			{
				error: "Route not found",
			},
			{
				status: 404,
			}
		);
	},
};