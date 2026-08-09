const controls = [

	{
		id: "AC-001",
		name: "Privileged Accounts Require MFA",
		objective:
			"All active privileged accounts must have multi-factor authentication enabled.",
	},

	{
		id: "AC-002",
		name: "Terminated Employees Must Not Retain Active Accounts",
		objective:
			"Accounts belonging to terminated employees must be deactivated.",
	},

	{
		id: "AC-003",
		name: "Privileged Access Reviews",
		objective:
			"Active privileged accounts must have an access review completed within the last 90 days.",
	},

];


const runAllButton =
	document.getElementById("runAllButton");

const controlsContainer =
	document.getElementById("controlsContainer");

const findingsList =
	document.getElementById("findingsList");

const assessmentTableBody =
	document.getElementById("assessmentTableBody");

const passingCount =
	document.getElementById("passingCount");

const failingCount =
	document.getElementById("failingCount");

const findingCount =
	document.getElementById("findingCount");

const criticalCount =
	document.getElementById("criticalCount");

const highCount =
	document.getElementById("highCount");

const highestRisk =
	document.getElementById("highestRisk");

const statusMessage =
	document.getElementById("statusMessage");


// ---------------------------------------------------------
// HELPERS
// ---------------------------------------------------------

function formatDate(dateString) {

	if (!dateString) {
		return "—";
	}

	return new Date(
		dateString
	).toLocaleString();
}


function showMessage(message) {

	statusMessage.textContent =
		message;

	statusMessage.style.display =
		"block";
}


function parseSummary(summary) {

	if (!summary) {

		return {
			riskSummary:
				"No AI summary available.",

			potentialImpact:
				"—",

			recommendedRemediation:
				"—",
		};
	}


	const riskMatch =
		summary.match(
			/Risk Summary:\s*([\s\S]*?)(?=\n\nPotential Impact:|$)/
		);


	const impactMatch =
		summary.match(
			/Potential Impact:\s*([\s\S]*?)(?=\n\nRecommended Remediation:|$)/
		);


	const remediationMatch =
		summary.match(
			/Recommended Remediation:\s*([\s\S]*)/
		);


	return {

		riskSummary:
			riskMatch
				? riskMatch[1].trim()
				: "No AI summary available.",

		potentialImpact:
			impactMatch
				? impactMatch[1].trim()
				: "—",

		recommendedRemediation:
			remediationMatch
				? remediationMatch[1].trim()
				: "—",
	};
}


// ---------------------------------------------------------
// LOAD DASHBOARD
// ---------------------------------------------------------

async function loadDashboard() {

	try {

		const [
			assessmentResponse,
			findingsResponse,
		] = await Promise.all([

			fetch(
				"/api/assessments"
			),

			fetch(
				"/api/findings"
			),

		]);


		const assessments =
			await assessmentResponse.json();


		const findings =
			await findingsResponse.json();


		renderControls(
			assessments,
			findings
		);


		renderFindings(
			findings
		);


		renderAssessmentHistory(
			assessments
		);


		updateMetrics(
			assessments,
			findings
		);

	} catch (error) {

		console.error(
			"Failed to load dashboard:",
			error
		);


		showMessage(
			"Unable to load dashboard data."
		);
	}
}


// ---------------------------------------------------------
// CONTROL CARDS
// ---------------------------------------------------------

function renderControls(
	assessments,
	findings
) {

	controlsContainer.innerHTML =
		controls
			.map((control) => {

				const latestAssessment =
					assessments.find(
						(assessment) =>
							assessment.control_id ===
							control.id
					);


				const controlFindings =
					findings.filter(
						(finding) =>
							finding.control_id ===
								control.id &&
							finding.status ===
								"OPEN"
					);


				const status =
					latestAssessment
						? latestAssessment.status
						: "UNKNOWN";


				const summary =
					parseSummary(
						latestAssessment?.summary
					);


				const evidenceHTML =
					latestAssessment?.evidence_key

						? `
							<a
								href="/api/evidence/${latestAssessment.evidence_key}"
								target="_blank"
							>
								View raw evidence
							</a>
						`

						: `
							<span class="muted">
								No evidence yet
							</span>
						`;


				const exceptionsHTML =
					controlFindings.length > 0

						? controlFindings
							.map(
								(finding) => `

									<div class="exception-row">

										<div class="exception-content">

											<div class="exception-title">

												<strong>
													${finding.subject}
												</strong>

												<span class="severity severity-${finding.severity.toLowerCase()}">
													${finding.severity}
												</span>

											</div>


											<p>
												${finding.description}
											</p>


											<div class="compact-risk">

												<span>
													Risk
													<strong>
														${finding.risk_score}/25
													</strong>
												</span>

												<span>
													Likelihood
													<strong>
														${finding.likelihood}/5
													</strong>
												</span>

												<span>
													Impact
													<strong>
														${finding.impact}/5
													</strong>
												</span>

											</div>

										</div>

									</div>
								`
							)
							.join("")

						: `
							<p class="muted">
								No open exceptions.
							</p>
						`;


				return `

					<div class="control-card">

						<div class="control-header">

							<div>

								<span class="control-id">
									${control.id}
								</span>

								<h3>
									${control.name}
								</h3>

							</div>


							<span
								class="status-badge ${status.toLowerCase()}"
							>
								${status}
							</span>

						</div>


						<div class="control-objective">

							<strong>
								Control Objective
							</strong>

							<p>
								${control.objective}
							</p>

						</div>


						<div class="control-meta">

							<div>
								<strong>
									Last Assessed
								</strong>

								<p>
									${latestAssessment
										? formatDate(
											latestAssessment.assessed_at
										)
										: "Never"}
								</p>
							</div>


							<div>
								<strong>
									Evidence
								</strong>

								<p>
									${evidenceHTML}
								</p>
							</div>

						</div>


						<div class="control-subsection">

							<h4>
								Exceptions
							</h4>

							${exceptionsHTML}

						</div>


						<div class="control-subsection">

							<h4>
								AI Risk Analysis
							</h4>


							<div class="ai-card">

								<div class="ai-section">

									<strong>
										Risk Summary
									</strong>

									<p>
										${summary.riskSummary}
									</p>

								</div>


								<div class="ai-section">

									<strong>
										Potential Impact
									</strong>

									<p>
										${summary.potentialImpact}
									</p>

								</div>


								<div class="ai-section">

									<strong>
										Recommended Remediation
									</strong>

									<p>
										${summary.recommendedRemediation}
									</p>

								</div>

							</div>

						</div>


						<div class="control-actions">

							<button
								class="secondary-button run-control-button"
								data-control="${control.id}"
							>
								Run ${control.id}
							</button>

						</div>

					</div>
				`;

			})
			.join("");


	document
		.querySelectorAll(
			".run-control-button"
		)
		.forEach((button) => {

			button.addEventListener(
				"click",
				() => {

					runControl(
						button.dataset.control,
						button
					);
				}
			);
		});
}


// ---------------------------------------------------------
// METRICS
// ---------------------------------------------------------

function updateMetrics(
	assessments,
	findings
) {

	let passing = 0;
	let failing = 0;


	for (const control of controls) {

		const latestAssessment =
			assessments.find(
				(assessment) =>
					assessment.control_id ===
					control.id
			);


		if (!latestAssessment) {
			continue;
		}


		if (
			latestAssessment.status ===
			"PASS"
		) {
			passing++;
		}


		if (
			latestAssessment.status ===
			"FAIL"
		) {
			failing++;
		}
	}


	const openFindings =
		findings.filter(
			(finding) =>
				finding.status ===
				"OPEN"
		);


	const criticalFindings =
		openFindings.filter(
			(finding) =>
				finding.severity ===
				"CRITICAL"
		);


	const highFindings =
		openFindings.filter(
			(finding) =>
				finding.severity ===
				"HIGH"
		);


	const highestScore =
		openFindings.reduce(
			(highest, finding) =>
				Math.max(
					highest,
					finding.risk_score ?? 0
				),
			0
		);


	passingCount.textContent =
		String(passing);

	failingCount.textContent =
		String(failing);

	findingCount.textContent =
		String(openFindings.length);

	criticalCount.textContent =
		String(criticalFindings.length);

	highCount.textContent =
		String(highFindings.length);

	highestRisk.textContent =
		String(highestScore);
}


// ---------------------------------------------------------
// FINDINGS
// ---------------------------------------------------------

function renderFindings(findings) {

	const openFindings =
		findings
			.filter(
				(finding) =>
					finding.status ===
						"OPEN"
			)
			.sort(
				(a, b) =>
					(b.risk_score ?? 0) -
					(a.risk_score ?? 0)
			);


	if (
		openFindings.length === 0
	) {

		findingsList.innerHTML = `
			<p class="muted">
				No open findings.
			</p>
		`;

		return;
	}


	findingsList.innerHTML =
		openFindings
			.map(
				(finding) => `

					<div class="finding">

						<div class="finding-header">

							<div>

								<strong class="finding-subject">
									${finding.subject}
								</strong>

								<span class="finding-control">
									${finding.control_id}
								</span>

							</div>


							<span class="severity severity-${finding.severity.toLowerCase()}">
								${finding.severity}
							</span>

						</div>


						<p class="finding-description">
							${finding.description}
						</p>


						<div class="risk-grid">

							<div class="risk-stat">

								<span class="risk-label">
									Risk Score
								</span>

								<strong class="risk-value">
									${finding.risk_score} / 25
								</strong>

							</div>


							<div class="risk-stat">

								<span class="risk-label">
									Likelihood
								</span>

								<strong class="risk-value">
									${finding.likelihood} / 5
								</strong>

							</div>


							<div class="risk-stat">

								<span class="risk-label">
									Impact
								</span>

								<strong class="risk-value">
									${finding.impact} / 5
								</strong>

							</div>

						</div>


						<div class="remediation-panel">

							<div class="remediation-item">

								<span class="remediation-label">
									Owner
								</span>

								<strong>
									${finding.owner || "Unassigned"}
								</strong>

							</div>


							<div class="remediation-item">

								<span class="remediation-label">
									Due Date
								</span>

								<strong>
									${formatDate(
										finding.due_date
									)}
								</strong>

							</div>


							<div class="remediation-item remediation-plan">

								<span class="remediation-label">
									Remediation Plan
								</span>

								<p>
									${finding.remediation || "No remediation plan assigned."}
								</p>

							</div>

						</div>


						<div class="finding-footer">

							<span class="finding-status">
								Status: ${finding.status}
							</span>


							<button
								class="resolve-button"
								data-finding-id="${finding.id}"
							>
								Resolve Finding
							</button>

						</div>

					</div>

				`
			)
			.join("");


	document
		.querySelectorAll(
			".resolve-button"
		)
		.forEach((button) => {

			button.addEventListener(
				"click",
				() => {

					resolveFinding(
						button.dataset.findingId,
						button
					);
				}
			);
		});
}


// ---------------------------------------------------------
// RESOLVE FINDING
// ---------------------------------------------------------

async function resolveFinding(
	findingId,
	button
) {

	const originalText =
		button.textContent;


	try {

		button.disabled =
			true;

		button.textContent =
			"Resolving...";


		const response =
			await fetch(
				`/api/findings/${findingId}/resolve`,
				{
					method:
						"POST",
				}
			);


		if (!response.ok) {

			throw new Error(
				"Unable to resolve finding"
			);
		}


		showMessage(
			`Finding ${findingId} resolved.`
		);


		await loadDashboard();

	} catch (error) {

		console.error(
			error
		);


		showMessage(
			`Finding ${findingId} could not be resolved.`
		);

	} finally {

		button.disabled =
			false;

		button.textContent =
			originalText;
	}
}


// ---------------------------------------------------------
// ASSESSMENT HISTORY
// ---------------------------------------------------------

function renderAssessmentHistory(
	assessments
) {

	if (
		assessments.length === 0
	) {

		assessmentTableBody.innerHTML = `

			<tr>
				<td colspan="5">
					No assessments yet.
				</td>
			</tr>

		`;

		return;
	}


	assessmentTableBody.innerHTML =
		assessments
			.map(
				(assessment) => {

					const evidence =
						assessment.evidence_key

							? `
								<a
									href="/api/evidence/${assessment.evidence_key}"
									target="_blank"
								>
									View
								</a>
							`

							: "—";


					return `

						<tr>

							<td>
								${assessment.id}
							</td>

							<td>
								${assessment.control_id}
							</td>

							<td>

								<span class="table-status ${assessment.status.toLowerCase()}">
									${assessment.status}
								</span>

							</td>

							<td>
								${formatDate(
									assessment.assessed_at
								)}
							</td>

							<td>
								${evidence}
							</td>

						</tr>

					`;

				}
			)
			.join("");
}


// ---------------------------------------------------------
// RUN ONE CONTROL
// ---------------------------------------------------------

async function runControl(
	controlId,
	button
) {

	const originalText =
		button.textContent;


	try {

		button.disabled =
			true;

		button.textContent =
			"Running...";


		showMessage(
			`Running ${controlId}...`
		);


		const response =
			await fetch(
				`/api/assess/${controlId}`
			);


		if (!response.ok) {

			throw new Error(
				`${controlId} failed`
			);
		}


		const result =
			await response.json();


		showMessage(
			`${controlId} completed: ${result.status}`
		);


		await loadDashboard();

	} catch (error) {

		console.error(
			error
		);


		showMessage(
			`${controlId} could not be completed.`
		);

	} finally {

		button.disabled =
			false;

		button.textContent =
			originalText;
	}
}


// ---------------------------------------------------------
// RUN ALL CONTROLS
// ---------------------------------------------------------

async function runAllControls() {

	runAllButton.disabled =
		true;

	runAllButton.textContent =
		"Running...";


	try {

		for (
			const control
			of controls
		) {

			showMessage(
				`Running ${control.id}...`
			);


			const response =
				await fetch(
					`/api/assess/${control.id}`
				);


			if (!response.ok) {

				throw new Error(
					`${control.id} failed`
				);
			}
		}


		showMessage(
			"All controls completed."
		);


		await loadDashboard();

	} catch (error) {

		console.error(
			"Control run failed:",
			error
		);


		showMessage(
			"One or more controls could not be completed."
		);

	} finally {

		runAllButton.disabled =
			false;

		runAllButton.textContent =
			"Run All Controls";
	}
}


// ---------------------------------------------------------
// EVENTS / INITIAL LOAD
// ---------------------------------------------------------

runAllButton.addEventListener(
	"click",
	runAllControls
);


loadDashboard();