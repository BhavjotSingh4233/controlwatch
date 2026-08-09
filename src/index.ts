import { users } from "./data";
import { checkPrivilegedMFA } from "./control";


// ---------------------------------------------------------
// CLOUDFLARE ENVIRONMENT
// ---------------------------------------------------------

interface Env {

	// D1 database for structured GRC records.
	controlwatch_db: D1Database;

	// R2 bucket for raw evidence.
	controlwatch_evidence: R2Bucket;

	// Cloudflare Workers AI.
	AI: Ai;
}


// ---------------------------------------------------------
// AI SUMMARY TYPE
// ---------------------------------------------------------

// This describes the structured object we want from Workers AI.
interface AIRiskSummary {
	riskSummary: string;
	potentialImpact: string;
	recommendedRemediation: string;
}


export default {

	async fetch(request: Request, env: Env): Promise<Response> {

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


			// -----------------------------------------------------
			// STEP 1: RUN DETERMINISTIC CONTROL
			// -----------------------------------------------------

			// Our TypeScript code decides PASS or FAIL.
			//
			// AI does NOT make this decision.
			const result = checkPrivilegedMFA();


			// Record when the assessment ran.
			const assessedAt = new Date().toISOString();


			// -----------------------------------------------------
			// STEP 2: CREATE ASSESSMENT IN D1
			// -----------------------------------------------------

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


			// Get the new assessment ID from D1.
			const assessmentId =
				assessmentInsert.meta.last_row_id;


			// -----------------------------------------------------
			// STEP 3: CREATE EVIDENCE KEY
			// -----------------------------------------------------

			// Example:
			//
			// AC-001/assessment-10.json
			const evidenceKey =
				`${result.controlId}/assessment-${assessmentId}.json`;


			// -----------------------------------------------------
			// STEP 4: BUILD RAW EVIDENCE
			// -----------------------------------------------------

			const evidence = {

				controlId: result.controlId,

				controlName: result.controlName,

				assessmentId: assessmentId,

				assessedAt: assessedAt,

				source: "synthetic-identity-data",

				users: users,
			};


			const evidenceJson =
				JSON.stringify(evidence, null, 2);


			// -----------------------------------------------------
			// STEP 5: SAVE RAW EVIDENCE INTO R2
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
			// STEP 6: LINK R2 EVIDENCE TO D1
			// -----------------------------------------------------

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
			// STEP 7: CREATE FINDINGS
			// -----------------------------------------------------

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

						assessmentId,

						result.controlId,

						"HIGH",

						failure.name,

						"Active privileged account does not have MFA enabled",

						"OPEN"
					)
					.run();
			}


			// -----------------------------------------------------
			// STEP 8: PREPARE INPUT FOR WORKERS AI
			// -----------------------------------------------------

			// Turn the actual failed users into JSON.
			//
			// This means Bob is NOT hard-coded into the AI logic.
			const exceptionsForAI =
				JSON.stringify(result.failures, null, 2);


			// -----------------------------------------------------
			// STEP 9: CALL WORKERS AI USING JSON MODE
			// -----------------------------------------------------

			let parsedAI: AIRiskSummary;


			try {

				const aiResponse = await env.AI.run(

					"@cf/meta/llama-3.1-8b-instruct-fast",

					{
						// The model still needs instructions about
						// what the data means.
						messages: [
							{
								role: "system",
								content:
									"You are a security Governance, Risk, and Compliance analyst. Explain deterministic control results to nontechnical security leaders. Never change the provided PASS or FAIL result and never invent facts.",
							},
							{
								role: "user",
								content: `
Analyze this already-completed security control assessment.

Control ID:
${result.controlId}

Control Name:
${result.controlName}

Deterministic Result:
${result.status}

Actual Exceptions:
${exceptionsForAI}

Create a concise executive explanation.

The risk summary should mention the actual affected person when applicable.
The recommended remediation should directly address the identified exception.
								`,
							},
						],


						// -------------------------------------------------
						// JSON MODE / STRUCTURED OUTPUT
						// -------------------------------------------------

						// Instead of asking the model to FORMAT JSON
						// correctly using only prompt instructions,
						// we give Workers AI an actual JSON schema.
						//
						// Cloudflare asks the model to return an object
						// conforming to this structure.
						response_format: {

							type: "json_schema",

							json_schema: {

								type: "object",

								properties: {

									riskSummary: {
										type: "string",
									},

									potentialImpact: {
										type: "string",
									},

									recommendedRemediation: {
										type: "string",
									},
								},

								required: [
									"riskSummary",
									"potentialImpact",
									"recommendedRemediation",
								],

								additionalProperties: false,
							},
						},
					}
				);


				// -----------------------------------------------------
				// STEP 10: READ STRUCTURED AI RESPONSE
				// -----------------------------------------------------

				// With JSON Mode, Cloudflare returns the structured
				// result through "response".
				const aiResult =
					(aiResponse as any).response;


				// Usually JSON Mode gives us an object directly.
				//
				// But we handle both possibilities:
				//
				// 1. response is already an object
				// 2. response happens to come back as JSON text
				if (typeof aiResult === "string") {

					parsedAI =
						JSON.parse(aiResult) as AIRiskSummary;

				} else {

					parsedAI =
						aiResult as AIRiskSummary;
				}


				// -----------------------------------------------------
				// STEP 11: VALIDATE REQUIRED FIELDS
				// -----------------------------------------------------

				// Even structured AI output should still be checked
				// before we trust it.
				if (
					!parsedAI ||
					!parsedAI.riskSummary ||
					!parsedAI.potentialImpact ||
					!parsedAI.recommendedRemediation
				) {

					throw new Error(
						"Workers AI response was missing required fields"
					);
				}

			} catch (error) {

				// -----------------------------------------------------
				// SAFE FALLBACK
				// -----------------------------------------------------

				// IMPORTANT:
				//
				// An AI failure does NOT change the actual
				// security assessment.
				//
				// The deterministic result remains the source of truth.
				console.error(
					"Workers AI summary generation failed:",
					error
				);


				parsedAI = {

					riskSummary:
						"AI risk summary could not be generated.",

					potentialImpact:
						"See the deterministic control result and supporting evidence.",

					recommendedRemediation:
						"Review and remediate the identified control exceptions.",
				};
			}


			// -----------------------------------------------------
			// STEP 12: CREATE SUMMARY TEXT FOR D1
			// -----------------------------------------------------

			// D1 currently has one TEXT column called "summary".
			//
			// So we'll save the structured fields as nicely
			// formatted text.
			const aiSummaryText = [

				`Risk Summary: ${parsedAI.riskSummary}`,

				`Potential Impact: ${parsedAI.potentialImpact}`,

				`Recommended Remediation: ${parsedAI.recommendedRemediation}`,

			].join("\n\n");


			// -----------------------------------------------------
			// STEP 13: SAVE AI SUMMARY INTO D1
			// -----------------------------------------------------

			await env.controlwatch_db
				.prepare(`
					UPDATE assessments
					SET summary = ?
					WHERE id = ?
				`)
				.bind(
					aiSummaryText,
					assessmentId
				)
				.run();


			// -----------------------------------------------------
			// STEP 14: RETURN COMPLETE ASSESSMENT
			// -----------------------------------------------------

			return Response.json({

				// Deterministic result.
				...result,

				assessmentId: assessmentId,

				assessedAt: assessedAt,

				evidenceKey: evidenceKey,


				// Structured AI explanation.
				aiSummary: {

					riskSummary:
						parsedAI.riskSummary,

					potentialImpact:
						parsedAI.potentialImpact,

					recommendedRemediation:
						parsedAI.recommendedRemediation,
				},


				savedToDatabase: true,

				savedEvidenceToR2: true,

				evidenceLinkedToAssessment: true,

				aiSummarySavedToDatabase: true,
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


			return Response.json(
				query.results
			);
		}


		// ---------------------------------------------------------
		// ROUTE 5: GET ALL ASSESSMENTS
		// ---------------------------------------------------------

		if (url.pathname === "/api/assessments") {

			const query = await env.controlwatch_db
				.prepare(`
					SELECT *
					FROM assessments
					ORDER BY id DESC
				`)
				.all();


			return Response.json(
				query.results
			);
		}


		// ---------------------------------------------------------
		// ROUTE 6: GET EVIDENCE FROM R2
		// ---------------------------------------------------------

		// Example:
		//
		// /api/evidence/AC-001/assessment-10.json
		if (
			url.pathname.startsWith(
				"/api/evidence/"
			)
		) {

			// Convert the API path into an R2 object key.
			const evidenceKey =
				url.pathname.replace(
					"/api/evidence/",
					""
				);


			const object =
				await env.controlwatch_evidence.get(
					evidenceKey
				);


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


			const evidenceText =
				await object.text();


			return new Response(
				evidenceText,
				{
					headers: {
						"Content-Type":
							"application/json",
					},
				}
			);
		}


		// ---------------------------------------------------------
		// ROUTE 7: AI CONNECTION TEST
		// ---------------------------------------------------------

		if (url.pathname === "/api/ai-test") {

			const aiResponse =
				await env.AI.run(

					"@cf/meta/llama-3.1-8b-instruct-fast",

					{
						prompt:
							"Return exactly this sentence: Workers AI is connected to ControlWatch.",
					}
				);


			return Response.json(
				aiResponse
			);
		}


		// ---------------------------------------------------------
		// ROUTE 8: NOT FOUND
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