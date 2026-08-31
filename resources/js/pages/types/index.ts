/**
 * The console's contract with the backend. Every shape here is produced by
 * an API resource in src/Http/Resources — not by an Eloquent model — so a
 * column rename on the PHP side cannot silently reshape this file.
 */

export type ScanStatus =
    | 'pending'
    | 'scanning'
    | 'clean'
    | 'suspicious'
    | 'infected'
    | 'failed'
    | 'quarantined';

export type ThreatLevel = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type ScanType = 'file' | 'text' | 'html' | 'url';

export type PostureState = 'healthy' | 'warning' | 'critical';

export interface Threat {
    id?: number;
    name: string;
    level: ThreatLevel;
    source: string;
    description: string | null;
    metadata?: Record<string, unknown>;
    created_at?: string | null;
}

export interface CheckOutcome {
    check: string;
    status: ScanStatus;
    skipped: boolean;
    duration_ms: number;
    error: string | null;
    metadata: Record<string, unknown>;
}

export interface Scan {
    id: string;
    short_id: string;
    type: ScanType;
    status: ScanStatus;
    scanner: string | null;
    policy: string | null;
    subject: string;
    extension: string | null;
    declared_mime: string | null;
    detected_mime: string | null;
    size: number | null;
    content_length: number | null;
    checksum: string | null;
    duration_ms: number;
    threat_count: number;
    quarantined: boolean;
    created_at: string | null;
    completed_at: string | null;
    quarantine_path?: string | null;
    threats?: Threat[];
    checks?: CheckOutcome[];
}

export interface ScannerHealth {
    scanner: string;
    /** `unconfigured` means the ACTIVE driver cannot scan; `inactive` is an idle driver. */
    status: 'online' | 'offline' | 'disabled' | 'inactive' | 'unconfigured';
    online: boolean;
    enabled: boolean;
    /** The driver the application actually scans with. */
    active: boolean;
    /** Only true when the active engine cannot scan. */
    is_problem: boolean;
    version: string | null;
    signature_version: string | null;
    signatures_updated_at: string | null;
    ping_ms: number | null;
    connection: string | null;
    error: string | null;
    details: Record<string, unknown>;
}

export interface Statistics {
    total: number;
    window_hours: number;
    window_total: number;
    clean: number;
    suspicious: number;
    infected: number;
    failed: number;
    quarantined: number;
    pending: number;
    avg_duration_ms: number;
    threats: number;
}

export interface Posture {
    state: PostureState;
    headline: string;
    detail: string;
}

export interface TimelinePoint {
    bucket: string;
    total: number;
    threats: number;
}

export interface ScanEvent {
    label: string;
    at: string | null;
    state: 'done' | 'pending' | 'alert';
}

export interface AggregatedThreat {
    name: string;
    level: ThreatLevel;
    source: string;
    occurrences: number;
    first_seen: string;
    last_seen: string;
}

export interface FilePolicy {
    name: string;
    label: string;
    type: 'file';
    max_size: number;
    extensions: string[];
    mime_types: string[];
    checks: Record<string, boolean>;
    on_threat: 'reject' | 'quarantine';
    forbidden_extensions: string[];
}

export interface TextPolicyShape {
    name: string;
    label: string;
    type: 'text';
    max_length: number;
    checks: Record<string, boolean>;
}

export interface Paginated<T> {
    data: T[];
    links?: unknown;
    meta?: {
        current_page: number;
        last_page: number;
        per_page: number;
        total: number;
        from: number | null;
        to: number | null;
    };
    current_page?: number;
    last_page?: number;
    total?: number;
}

/** Shared from the service provider via Inertia. */
export interface ConsoleShared {
    basePath: string;
    brand: string;
    backUrl: string;
    backLabel: string;
    exposePaths: boolean;
}
