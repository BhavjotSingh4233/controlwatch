import { users } from "./data";

import {
	checkPrivilegedMFA,
	checkTerminatedAccounts,
	checkPrivilegedAccessReviews,
} from "./control";


// Cloudflare bindings.
interface Env {
	controlwatch_db: D1Database;
	controlwatch_evidence: R2Bucket;
	AI: Ai;
}


interface AIRiskSummary {
	riskSummary: string;
	potentialImpact: string;
	recommendedRemediation: string;
}


interface ControlResult {
	controlId: string;
	controlName: string;
	status: string;
	failures: typeof users;
}


// Configuration for each internal control.
const controlDetails: Record<
	string,
	{
		likelihood: number;
		impact: number;
		description: string;
		owner: string;
		remediation: string;
	}
> = {

	"AC-001": {
		likelihood: 4,
		impact: 5,

		description:
			"Active privileged account does not have MFA enabled",

		owner:
			"Identity Security",

		remediation:
			"Enable MFA for the affected privileged account and verify MFA enforcement for all privileged users.",
	},


	"AC-002": {
		likelihood: 4,
		impact: 5,

		description:
			"Terminated employee still has an active account",

		owner:
			"IT Operations",

		remediation:
			"Disable the terminated employee account and verify the offboarding process removes access promptly.",
	},


	"AC-003": {
		likelihood: 3,
		impact: 4,

		description:
			"Privileged account has not completed an access review within 90 days",

		owner:
			"Identity Governance",

		remediation:
			"Perform the overdue privileged access review and confirm the user's current access remains justified.",
	},
};


// ---------------------------------------------------------
// RISK HELPERS
// ---------------------------------------------------------

function getSeverity(
	riskScore: number
): string {

	if (riskScore >= 20) {
		return "CRITICAL";
	}

	if (riskScore >= 12) {
		return "HIGH";
	}

	if (riskScore >= 6) {
		return "MEDIUM";
	}

	return "LOW";
}


function calculateDueDate(
	severity: string,
	createdAt: string
): string {

	const daysBySeverity: Record<string, number> = {
		CRITICAL: 3,
		HIGH: 7,
		MEDIUM: 14,
		LOW: 30,
	};


	const days =
		daysBySeverity[severity] ?? 30;


	const dueDate =
		new Date(createdAt);


	dueDate.setUTCDate(
		dueDate.getUTCDate() +
		days
	);


	return dueDate.toISOString();
}


// ---------------------------------------------------------
// AI INPUT
// ---------------------------------------------------------

function getAIExceptions(
	result: ControlResult
) {

	switch (result.controlId) {

		case "AC-001":

			return result.failures.map(
				(user) => ({
					id: user.id,
					name: user.name,
					role: user.role,
					active: user.active,
					mfa: user.mfa,
				})
			);


		case "AC-002":

			return result.failures.map(
				(user) => ({
					id: user.id,
					name: user.name,
					role: user.role,
					active: user.active,
					employmentStatus:
						user.employmentStatus,
				})
			);


		case "AC-003":

			return result.failures.map(
				(user) => ({
					id: user.id,
					name: user.name,
					role: user.role,
					active: user.active,
					lastAccessReview:
						user.lastAccessReview,
				})
			);


		default:

			return result.failures;
	}
}


// ---------------------------------------------------------
// SHARED ASSESSMENT PIPELINE
// ---------------------------------------------------------

async function processAssessment(
	result: ControlResult,
	env: Env
): Promise<Response> {

	const assessedAt =
		new Date().toISOString();


	// Create assessment record.
	const assessmentInsert =
		await env.controlwatch_db
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


	const assessmentId =
		assessmentInsert.meta.last_row_id;


	// ---------------------------------------------------------
	// EVIDENCE
	// ---------------------------------------------------------

	const evidenceKey =
		`${result.controlId}/assessment-${assessmentId}.json`;


	const evidence = {

		controlId:
			result.controlId,

		controlName:
			result.controlName,

		assessmentId,

		assessedAt,

		source:
			"synthetic-identity-data",

		users,
	};


	await env.controlwatch_evidence.put(

		evidenceKey,

		JSON.stringify(
			evidence,
			null,
			2
		),

		{
			httpMetadata: {
				contentType:
					"application/json",
			},
		}
	);


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


	// ---------------------------------------------------------
	// RISK
	// ---------------------------------------------------------

	const details =
		controlDetails[
			result.controlId
		];


	const likelihood =
		details?.likelihood ?? 1;


	const impact =
		details?.impact ?? 1;


	const riskScore =
		likelihood * impact;


	const severity =
		getSeverity(
			riskScore
		);


	const dueDate =
		calculateDueDate(
			severity,
			assessedAt
		);


	// ---------------------------------------------------------
	// FINDING LIFECYCLE
	// ---------------------------------------------------------

	for (const failure of result.failures) {

		const existingFinding =
			await env.controlwatch_db
				.prepare(`
					SELECT *
					FROM findings
					WHERE control_id = ?
					AND subject = ?
					AND status = 'OPEN'
					LIMIT 1
				`)
				.bind(
					result.controlId,
					failure.name
				)
				.first();


		if (!existingFinding) {

			await env.controlwatch_db
				.prepare(`
					INSERT INTO findings (
						assessment_id,
						control_id,
						severity,
						subject,
						description,
						status,
						likelihood,
						impact,
						risk_score,
						owner,
						due_date,
						remediation
					)
					VALUES (
						?, ?, ?, ?, ?, ?,
						?, ?, ?, ?, ?, ?
					)
				`)
				.bind(
					assessmentId,

					result.controlId,

					severity,

					failure.name,

					details?.description ??
						"Security control exception detected",

					"OPEN",

					likelihood,

					impact,

					riskScore,

					details?.owner ??
						"Security",

					dueDate,

					details?.remediation ??
						"Review and remediate the security control exception."
				)
				.run();

		} else {

			// Keep current risk/remediation metadata without
			// pushing the original deadline forward.
			await env.controlwatch_db
				.prepare(`
					UPDATE findings
					SET
						severity = ?,
						likelihood = ?,
						impact = ?,
						risk_score = ?,
						owner = ?,
						remediation = ?,
						due_date = COALESCE(
							due_date,
							?
						)
					WHERE id = ?
				`)
				.bind(
					severity,

					likelihood,

					impact,

					riskScore,

					details?.owner ??
						"Security",

					details?.remediation ??
						"Review and remediate the security control exception.",

					dueDate,

					(existingFinding as any)
						.id
				)
				.run();
		}
	}


	// Automatically resolve issues that disappear
	// from a later deterministic assessment.
	const openFindings =
		await env.controlwatch_db
			.prepare(`
				SELECT *
				FROM findings
				WHERE control_id = ?
				AND status = 'OPEN'
			`)
			.bind(
				result.controlId
			)
			.all();


	for (
		const finding
		of openFindings.results as any[]
	) {

		const stillFailing =
			result.failures.some(
				(failure) =>
					failure.name ===
					finding.subject
			);


		if (!stillFailing) {

			await env.controlwatch_db
				.prepare(`
					UPDATE findings
					SET
						status = 'RESOLVED',
						resolved_at = ?
					WHERE id = ?
				`)
				.bind(
					assessedAt,
					finding.id
				)
				.run();
		}
	}


	// ---------------------------------------------------------
	// WORKERS AI
	// ---------------------------------------------------------

	const aiExceptions =
		getAIExceptions(
			result
		);


	const exceptionsForAI =
		JSON.stringify(
			aiExceptions,
			null,
			2
		);


	let parsedAI: AIRiskSummary;


	try {

		const aiResponse =
			await env.AI.run(

				"@cf/meta/llama-3.1-8b-instruct-fast",

				{
					messages: [

						{
							role:
								"system",

							content:
								"You are a security Governance, Risk, and Compliance analyst. Explain deterministic security-control results to nontechnical security leaders. Never change the supplied PASS or FAIL result and never invent facts.",
						},

						{
							role:
								"user",

							content: `
Analyze this completed security control assessment.

Control ID:
${result.controlId}

Control Name:
${result.controlName}

Deterministic Result:
${result.status}

Exceptions:
${exceptionsForAI}

Risk Methodology:
Likelihood: ${likelihood}/5
Impact: ${impact}/5
Risk Score: ${riskScore}/25
Severity: ${severity}

Assigned Owner:
${details?.owner ?? "Security"}

Defined Remediation:
${details?.remediation ?? "Review the finding."}

Create a concise executive explanation.

Requirements:
- riskSummary must be one complete sentence describing the security risk.
- potentialImpact must be one complete sentence describing what could happen if the issue is exploited or remains unresolved.
- recommendedRemediation must be one complete sentence describing the specific action required to resolve the current exception.
- Reference affected users when appropriate.
- Only discuss information relevant to this control.
- Do not introduce unrelated security issues.
- Do not return a severity label by itself as potentialImpact.
- If a requirement is already overdue, remediation must address it immediately.
- Keep each field under 30 words.
							`,
						},
					],


					response_format: {

						type:
							"json_schema",

						json_schema: {

							type:
								"object",

							properties: {

								riskSummary: {
									type:
										"string",
								},

								potentialImpact: {
									type:
										"string",
								},

								recommendedRemediation: {
									type:
										"string",
								},
							},

							required: [
								"riskSummary",
								"potentialImpact",
								"recommendedRemediation",
							],

							additionalProperties:
								false,
						},
					},
				}
			);


		const aiResult =
			(aiResponse as any)
				.response;


		if (
			typeof aiResult ===
			"string"
		) {

			parsedAI =
				JSON.parse(
					aiResult
				) as AIRiskSummary;

		} else {

			parsedAI =
				aiResult as AIRiskSummary;
		}


		if (
			!parsedAI ||
			!parsedAI.riskSummary ||
			!parsedAI.potentialImpact ||
			!parsedAI.recommendedRemediation
		) {

			throw new Error(
				"Incomplete Workers AI response"
			);
		}

	} catch (error) {

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


	const aiSummaryText = [

		`Risk Summary: ${parsedAI.riskSummary}`,

		`Potential Impact: ${parsedAI.potentialImpact}`,

		`Recommended Remediation: ${parsedAI.recommendedRemediation}`,

	].join("\n\n");


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


	return Response.json({

		...result,

		assessmentId,

		assessedAt,

		evidenceKey,

		risk: {
			likelihood,
			impact,
			score:
				riskScore,
			maxScore:
				25,
			severity,
		},

		remediationTracking: {

			owner:
				details?.owner ??
				"Security",

			dueDate,

			remediation:
				details?.remediation ??
				"Review and remediate the security control exception.",
		},

		aiSummary: {

			riskSummary:
				parsedAI.riskSummary,

			potentialImpact:
				parsedAI.potentialImpact,

			recommendedRemediation:
				parsedAI.recommendedRemediation,
		},

		savedToDatabase:
			true,

		savedEvidenceToR2:
			true,

		evidenceLinkedToAssessment:
			true,

		aiSummarySavedToDatabase:
			true,
	});
}


// ---------------------------------------------------------
// WORKER ROUTES
// ---------------------------------------------------------

export default {

	async fetch(
		request: Request,
		env: Env
	): Promise<Response> {

		const url =
			new URL(
				request.url
			);


		if (
			url.pathname === "/"
		) {

			return Response.json({
				name:
					"ControlWatch",

				description:
					"Automated GRC control monitoring",
			});
		}


		if (
			url.pathname ===
			"/api/users"
		) {

			return Response.json(
				users
			);
		}


		// AC-001
		if (
			url.pathname ===
			"/api/assess/AC-001"
		) {

			return processAssessment(
				checkPrivilegedMFA(),
				env
			);
		}


		// AC-002
		if (
			url.pathname ===
			"/api/assess/AC-002"
		) {

			return processAssessment(
				checkTerminatedAccounts(),
				env
			);
		}


		// AC-003
		if (
			url.pathname ===
			"/api/assess/AC-003"
		) {

			return processAssessment(
				checkPrivilegedAccessReviews(),
				env
			);
		}


		// ---------------------------------------------------------
		// FINDINGS
		// ---------------------------------------------------------

		if (
			url.pathname ===
			"/api/findings"
		) {

			const query =
				await env.controlwatch_db
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
		// RESOLVE FINDING
		// ---------------------------------------------------------

		// Example:
		// POST /api/findings/14/resolve
		const resolveMatch =
			url.pathname.match(
				/^\/api\/findings\/(\d+)\/resolve$/
			);


		if (
			resolveMatch &&
			request.method === "POST"
		) {

			const findingId =
				Number(
					resolveMatch[1]
				);


			const finding =
				await env.controlwatch_db
					.prepare(`
						SELECT *
						FROM findings
						WHERE id = ?
					`)
					.bind(
						findingId
					)
					.first();


			if (!finding) {

				return Response.json(
					{
						error:
							"Finding not found",
					},
					{
						status: 404,
					}
				);
			}


			if (
				(finding as any).status ===
				"RESOLVED"
			) {

				return Response.json(
					{
						message:
							"Finding is already resolved",
						finding,
					}
				);
			}


			const resolvedAt =
				new Date().toISOString();


			await env.controlwatch_db
				.prepare(`
					UPDATE findings
					SET
						status = 'RESOLVED',
						resolved_at = ?
					WHERE id = ?
				`)
				.bind(
					resolvedAt,
					findingId
				)
				.run();


			return Response.json({
				id:
					findingId,

				status:
					"RESOLVED",

				resolvedAt,
			});
		}


		// ---------------------------------------------------------
		// ASSESSMENTS
		// ---------------------------------------------------------

		if (
			url.pathname ===
			"/api/assessments"
		) {

			const query =
				await env.controlwatch_db
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
		// EVIDENCE
		// ---------------------------------------------------------

		if (
			url.pathname.startsWith(
				"/api/evidence/"
			)
		) {

			const evidenceKey =
				url.pathname.replace(
					"/api/evidence/",
					""
				);


			const object =
				await env
					.controlwatch_evidence
					.get(
						evidenceKey
					);


			if (
				object === null
			) {

				return Response.json(
					{
						error:
							"Evidence not found",
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
		// AI CONNECTION TEST
		// ---------------------------------------------------------

		if (
			url.pathname ===
			"/api/ai-test"
		) {

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


		return Response.json(
			{
				error:
					"Route not found",
			},
			{
				status: 404,
			}
		);
	},
};