-- ThreatLens SQLite Schema (Local First, WAL-Enabled)

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,         -- PROCESS_STARTED, FILE_CREATED, FILE_MODIFIED, etc.
    process_id INTEGER,
    process_name TEXT,
    application TEXT,
    action TEXT NOT NULL,
    target TEXT,
    risk_score INTEGER DEFAULT 0,     -- 0 to 100
    severity TEXT DEFAULT 'Low',      -- Low, Medium, High, Critical
    explanation TEXT,                 -- Human-readable explanation
    technical_details TEXT            -- JSON or raw formatted diagnostic details
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);

CREATE TABLE IF NOT EXISTS processes (
    pid INTEGER PRIMARY KEY,
    ppid INTEGER,
    name TEXT NOT NULL,
    exe_path TEXT,
    cmdline TEXT,
    username TEXT,
    start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_signed INTEGER DEFAULT 0,
    risk_score INTEGER DEFAULT 0,
    status TEXT DEFAULT 'RUNNING'      -- RUNNING, TERMINATED
);

CREATE INDEX IF NOT EXISTS idx_processes_status ON processes(status);

CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    exe_path TEXT,
    trust_score INTEGER DEFAULT 80,    -- 0 to 100
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    description TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    risk_level TEXT NOT NULL,          -- Medium, High, Critical
    process_id INTEGER,
    source TEXT,                       -- Behavioral, FileWatcher, ProcessMonitor
    is_resolved INTEGER DEFAULT 0,     -- 0 = Active, 1 = Resolved/Dismissed
    recommendation TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_unresolved ON alerts(is_resolved, timestamp DESC);

CREATE TABLE IF NOT EXISTS quarantine (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_path TEXT NOT NULL,
    quarantine_path TEXT NOT NULL,
    quarantined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    reason TEXT NOT NULL,
    detection_source TEXT,
    status TEXT DEFAULT 'QUARANTINED'  -- QUARANTINED, RESTORED, DELETED
);

CREATE TABLE IF NOT EXISTS system_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    category TEXT NOT NULL,            -- STARTUP, SERVICE, REGISTRY, INSTALLATION
    description TEXT NOT NULL,
    process_id INTEGER,
    target TEXT,
    details TEXT
);

CREATE INDEX IF NOT EXISTS idx_sys_changes_time ON system_changes(timestamp DESC);

CREATE TABLE IF NOT EXISTS network_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    process_id INTEGER,
    process_name TEXT,
    protocol TEXT DEFAULT 'TCP',
    local_address TEXT,
    remote_address TEXT,
    remote_port INTEGER,
    domain TEXT,
    status TEXT,
    risk_level TEXT DEFAULT 'Low',
    explanation TEXT
);

CREATE INDEX IF NOT EXISTS idx_net_timestamp ON network_events(timestamp DESC);

CREATE TABLE IF NOT EXISTS app_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_name TEXT NOT NULL UNIQUE,
    exe_path TEXT,
    trust_score INTEGER DEFAULT 80,
    habitual_ports TEXT,               -- JSON list of ports normally used
    habitual_dirs TEXT,                -- JSON list of directories normally accessed
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_trusted INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS user_decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    target_identifier TEXT NOT NULL UNIQUE, -- File hash or path or app name
    decision TEXT NOT NULL,            -- ALLOW, BLOCK, QUARANTINE
    reason TEXT,
    expires_at DATETIME
);

