-- Stores every security control assessment run.
CREATE TABLE assessments (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    control_id TEXT NOT NULL,

    status TEXT NOT NULL,

    assessed_at TEXT NOT NULL,

    evidence_key TEXT,

    summary TEXT
);


CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL,
    control_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    subject TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN',
    resolved_at TEXT,

    likelihood INTEGER,
    impact INTEGER,
    risk_score INTEGER,

    owner TEXT,
    due_date TEXT,
    remediation TEXT
);