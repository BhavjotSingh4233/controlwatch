-- This table stores every time we run a security control.
CREATE TABLE assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    control_id TEXT NOT NULL,
    status TEXT NOT NULL,
    assessed_at TEXT NOT NULL,
    evidence_key TEXT,
    summary TEXT
);


-- This table stores specific security problems discovered
-- during an assessment.
CREATE TABLE findings (

    -- Unique ID for each finding.
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Which assessment discovered this problem?
    assessment_id INTEGER NOT NULL,

    -- Which security control does the problem relate to?
    control_id TEXT NOT NULL,

    -- How serious is the finding?
    severity TEXT NOT NULL,

    -- Who or what caused the finding?
    -- Example: "Bob"
    subject TEXT NOT NULL,

    -- Human-readable explanation of the problem.
    description TEXT NOT NULL,

    -- Is this problem still unresolved?
    status TEXT NOT NULL DEFAULT 'OPEN'
);