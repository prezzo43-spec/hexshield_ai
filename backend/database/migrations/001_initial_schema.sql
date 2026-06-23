-- =============================================================================
-- HexShield AI: Multi-Layered Forensic Engine for Malicious Streams and
-- Manipulated Media
-- =============================================================================
-- Schema Version : 1.0.0
-- Database       : PostgreSQL 16 (Neon Serverless)
-- Compliance     : ISO/IEC 27037 Digital Evidence Standards
-- Jurisdiction   : Kenya (Computer Misuse and Cybercrimes Act 2018)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- EXTENSIONS
-- -----------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =============================================================================
-- SECTION 1: ENUMERATED TYPES
-- =============================================================================

CREATE TYPE case_status AS ENUM (
    'OPEN',
    'UNDER_ANALYSIS',
    'PENDING_REVIEW',
    'CLOSED',
    'ARCHIVED',
    'REFERRED'
);

CREATE TYPE case_classification AS ENUM (
    'UNCLASSIFIED',
    'CONFIDENTIAL',
    'RESTRICTED',
    'TOP_SECRET'
);

CREATE TYPE entropy_verdict AS ENUM (
    'NORMAL',
    'ELEVATED',
    'CRITICAL'
);

CREATE TYPE media_type AS ENUM (
    'IMAGE',
    'VIDEO',
    'AUDIO',
    'UNKNOWN'
);

CREATE TYPE ai_verdict AS ENUM (
    'AUTHENTIC',
    'SUSPICIOUS',
    'MANIPULATED',
    'INCONCLUSIVE'
);

CREATE TYPE custody_event_type AS ENUM (
    'ACQUISITION',
    'TRANSFER',
    'ANALYSIS',
    'STORAGE',
    'EXPORT',
    'VERIFICATION',
    'DUPLICATION',
    'DISPOSITION'
);

CREATE TYPE report_type AS ENUM (
    'TRIAGE_SUMMARY',
    'FULL_FORENSIC',
    'CHAIN_OF_CUSTODY',
    'COURT_SUBMISSION',
    'AI_ANALYSIS_DETAIL'
);

CREATE TYPE report_format AS ENUM (
    'PDF',
    'JSON',
    'XML',
    'HTML'
);

CREATE TYPE investigator_role AS ENUM (
    'SYSTEM_ADMIN',
    'LEAD_INVESTIGATOR',
    'FORENSIC_ANALYST',
    'REVIEWING_OFFICER',
    'PROSECUTOR',
    'RESEARCHER',
    'READ_ONLY'
);

CREATE TYPE audit_event_category AS ENUM (
    'AUTH',
    'FILE_ACCESS',
    'ANALYSIS',
    'REPORT',
    'CONFIG',
    'ERROR',
    'SECURITY'
);

CREATE TYPE threat_relevance AS ENUM (
    'CRITICAL',
    'HIGH',
    'MEDIUM',
    'LOW',
    'INFORMATIONAL'
);

-- =============================================================================
-- SECTION 2: CORE TABLES
-- =============================================================================

CREATE TABLE investigators (
    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    full_name           VARCHAR(255)    NOT NULL,
    email               VARCHAR(255)    NOT NULL UNIQUE,
    badge_number        VARCHAR(100)    NULL,
    organization        VARCHAR(255)    NOT NULL,
    department          VARCHAR(255)    NULL,
    role                investigator_role   NOT NULL DEFAULT 'FORENSIC_ANALYST',
    is_active           BOOLEAN         NOT NULL DEFAULT TRUE,
    public_key_pem      TEXT            NULL,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    last_login_at       TIMESTAMPTZ     NULL,
    CONSTRAINT chk_investigators_email_format
        CHECK (email ~* '^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')
);

CREATE TABLE cases (
    id                      UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    case_reference          VARCHAR(100)    NOT NULL UNIQUE,
    case_title              VARCHAR(500)    NOT NULL,
    description             TEXT            NULL,
    status                  case_status     NOT NULL DEFAULT 'OPEN',
    classification          case_classification NOT NULL DEFAULT 'CONFIDENTIAL',
    jurisdiction            VARCHAR(255)    NOT NULL DEFAULT 'Republic of Kenya',
    applicable_law          TEXT            NULL,
    court_reference         VARCHAR(255)    NULL,
    suspect_reference       VARCHAR(255)    NULL,
    lead_investigator_id    UUID            NOT NULL
                            REFERENCES investigators(id)
                            ON DELETE RESTRICT,
    incident_location       VARCHAR(500)    NULL,
    incident_date           DATE            NULL,
    created_at              TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    closed_at               TIMESTAMPTZ     NULL,
    CONSTRAINT chk_cases_closed_after_created
        CHECK (closed_at IS NULL OR closed_at >= created_at)
);

CREATE TABLE file_submissions (
    id                      UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id                 UUID            NOT NULL
                            REFERENCES cases(id)
                            ON DELETE RESTRICT,
    submitted_by            UUID            NOT NULL
                            REFERENCES investigators(id)
                            ON DELETE RESTRICT,
    original_filename       VARCHAR(1000)   NOT NULL,
    stored_filename         VARCHAR(1000)   NOT NULL UNIQUE,
    file_extension          VARCHAR(50)     NULL,
    file_size_bytes         BIGINT          NOT NULL
                            CHECK (file_size_bytes > 0),
    mime_type_declared      VARCHAR(255)    NULL,
    mime_type_detected      VARCHAR(255)    NULL,
    sha256_hash             CHAR(64)        NOT NULL,
    sha512_hash             CHAR(128)       NOT NULL,
    storage_path            TEXT            NOT NULL,
    source_description      TEXT            NULL,
    submission_notes        TEXT            NULL,
    hex_analysis_complete   BOOLEAN         NOT NULL DEFAULT FALSE,
    ai_analysis_complete    BOOLEAN         NOT NULL DEFAULT FALSE,
    report_generated        BOOLEAN         NOT NULL DEFAULT FALSE,
    ingestion_timestamp     TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_file_sha256_length
        CHECK (length(sha256_hash) = 64),
    CONSTRAINT chk_file_sha512_length
        CHECK (length(sha512_hash) = 128)
);

-- =============================================================================
-- SECTION 3: REFERENCE TABLES
-- =============================================================================

CREATE TABLE magic_byte_signatures (
    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    format_name         VARCHAR(100)    NOT NULL,
    common_extensions   TEXT[]          NOT NULL,
    mime_type           VARCHAR(255)    NOT NULL,
    hex_signature       VARCHAR(256)    NOT NULL,
    byte_offset         INTEGER         NOT NULL DEFAULT 0,
    signature_length    INTEGER         NOT NULL,
    threat_relevance    threat_relevance    NOT NULL DEFAULT 'INFORMATIONAL',
    description         TEXT            NOT NULL,
    is_active           BOOLEAN         NOT NULL DEFAULT TRUE,
    source_reference    TEXT            NULL,
    added_at            TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    added_by            UUID            NULL
                        REFERENCES investigators(id)
                        ON DELETE SET NULL,
    CONSTRAINT chk_magic_hex_signature_format
        CHECK (hex_signature ~ '^[0-9A-Fa-f]+$'),
    CONSTRAINT chk_magic_signature_length_match
        CHECK (signature_length = length(hex_signature) / 2),
    CONSTRAINT chk_magic_byte_offset_non_negative
        CHECK (byte_offset >= 0)
);

-- =============================================================================
-- SECTION 4: ANALYSIS LAYER TABLES
-- =============================================================================

CREATE TABLE hex_analysis_results (
    id                          UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    submission_id               UUID            NOT NULL UNIQUE
                                REFERENCES file_submissions(id)
                                ON DELETE RESTRICT,
    shannon_entropy             NUMERIC(10, 6)  NOT NULL
                                CHECK (shannon_entropy >= 0 AND shannon_entropy <= 8),
    entropy_threshold_used      NUMERIC(10, 6)  NOT NULL,
    entropy_verdict             entropy_verdict NOT NULL,
    magic_bytes_extracted       VARCHAR(512)    NOT NULL,
    matched_signature_id        UUID            NULL
                                REFERENCES magic_byte_signatures(id)
                                ON DELETE SET NULL,
    mime_spoof_detected         BOOLEAN         NOT NULL DEFAULT FALSE,
    mime_spoof_details          TEXT            NULL,
    file_header_valid           BOOLEAN         NOT NULL DEFAULT TRUE,
    header_anomalies_detected   BOOLEAN         NOT NULL DEFAULT FALSE,
    header_anomaly_details      TEXT            NULL,
    byte_distribution_json      JSONB           NULL,
    suspicious_sections_json    JSONB           NULL,
    overall_risk_level          VARCHAR(20)     NOT NULL
                                CHECK (overall_risk_level IN ('CLEAN', 'SUSPICIOUS', 'MALICIOUS', 'UNKNOWN')),
    risk_summary                TEXT            NULL,
    analysis_duration_ms        INTEGER         NULL
                                CHECK (analysis_duration_ms >= 0),
    engine_version              VARCHAR(50)     NOT NULL,
    analyzed_by                 UUID            NULL
                                REFERENCES investigators(id)
                                ON DELETE SET NULL,
    analyzed_at                 TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE TABLE ai_media_analysis_results (
    id                              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    submission_id                   UUID            NOT NULL UNIQUE
                                    REFERENCES file_submissions(id)
                                    ON DELETE RESTRICT,
    media_type                      media_type      NOT NULL,
    authenticity_score              NUMERIC(5, 4)   NOT NULL
                                    CHECK (authenticity_score >= 0 AND authenticity_score <= 1),
    manipulation_confidence         NUMERIC(5, 4)   NOT NULL
                                    CHECK (manipulation_confidence >= 0 AND manipulation_confidence <= 1),
    verdict                         ai_verdict      NOT NULL,
    model_name                      VARCHAR(255)    NOT NULL,
    model_version                   VARCHAR(100)    NOT NULL,
    model_weights_hash              CHAR(64)        NULL,
    face_regions_detected_json      JSONB           NULL,
    compression_artifact_score      NUMERIC(5, 4)   NULL,
    noise_pattern_anomaly_score     NUMERIC(5, 4)   NULL,
    ela_anomaly_score               NUMERIC(5, 4)   NULL,
    total_frames_analyzed           INTEGER         NULL
                                    CHECK (total_frames_analyzed IS NULL OR total_frames_analyzed >= 0),
    temporal_inconsistency_score    NUMERIC(5, 4)   NULL,
    temporal_inconsistencies_json   JSONB           NULL,
    total_segments_analyzed         INTEGER         NULL
                                    CHECK (total_segments_analyzed IS NULL OR total_segments_analyzed >= 0),
    spectral_analysis_json          JSONB           NULL,
    voice_synthesis_score           NUMERIC(5, 4)   NULL,
    processing_duration_ms          INTEGER         NULL
                                    CHECK (processing_duration_ms IS NULL OR processing_duration_ms >= 0),
    inference_device                VARCHAR(50)     NULL,
    analyzed_by                     UUID            NULL
                                    REFERENCES investigators(id)
                                    ON DELETE SET NULL,
    analyzed_at                     TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE TABLE ai_analysis_frame_details (
    id                          UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    ai_analysis_id              UUID            NOT NULL
                                REFERENCES ai_media_analysis_results(id)
                                ON DELETE CASCADE,
    frame_index                 INTEGER         NOT NULL
                                CHECK (frame_index >= 0),
    timestamp_ms                INTEGER         NOT NULL
                                CHECK (timestamp_ms >= 0),
    anomaly_score               NUMERIC(5, 4)   NOT NULL
                                CHECK (anomaly_score >= 0 AND anomaly_score <= 1),
    is_flagged                  BOOLEAN         NOT NULL DEFAULT FALSE,
    frame_features_json         JSONB           NULL,
    recorded_at                 TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_frame_per_analysis
        UNIQUE (ai_analysis_id, frame_index)
);

-- =============================================================================
-- SECTION 5: FORENSIC COMPLIANCE TABLES
-- =============================================================================

CREATE TABLE chain_of_custody_events (
    id                      UUID                PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id                 UUID                NOT NULL
                            REFERENCES cases(id)
                            ON DELETE RESTRICT,
    submission_id           UUID                NULL
                            REFERENCES file_submissions(id)
                            ON DELETE RESTRICT,
    event_type              custody_event_type  NOT NULL,
    event_sequence          INTEGER             NOT NULL
                            CHECK (event_sequence > 0),
    actor_id                UUID                NOT NULL
                            REFERENCES investigators(id)
                            ON DELETE RESTRICT,
    actor_role              investigator_role   NOT NULL,
    actor_badge_number      VARCHAR(100)        NULL,
    event_description       TEXT                NOT NULL,
    location_description    VARCHAR(500)        NULL,
    hash_at_event           CHAR(64)            NULL,
    hash_verified           BOOLEAN             NULL,
    digital_signature       TEXT                NULL,
    record_hash             CHAR(64)            NULL,
    is_verified             BOOLEAN             NOT NULL DEFAULT FALSE,
    verified_by             UUID                NULL
                            REFERENCES investigators(id)
                            ON DELETE SET NULL,
    verified_at             TIMESTAMPTZ         NULL,
    notes                   TEXT                NULL,
    event_timestamp         TIMESTAMPTZ         NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_custody_hash_length
        CHECK (hash_at_event IS NULL OR length(hash_at_event) = 64),
    CONSTRAINT chk_custody_verified_requires_verifier
        CHECK (
            (is_verified = FALSE) OR
            (is_verified = TRUE AND verified_by IS NOT NULL AND verified_at IS NOT NULL)
        )
);

CREATE TABLE forensic_reports (
    id                      UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    submission_id           UUID            NULL
                            REFERENCES file_submissions(id)
                            ON DELETE RESTRICT,
    case_id                 UUID            NOT NULL
                            REFERENCES cases(id)
                            ON DELETE RESTRICT,
    report_type             report_type     NOT NULL,
    report_format           report_format   NOT NULL DEFAULT 'PDF',
    report_filename         VARCHAR(500)    NOT NULL,
    storage_path            TEXT            NOT NULL,
    file_size_bytes         BIGINT          NOT NULL
                            CHECK (file_size_bytes > 0),
    report_hash             CHAR(64)        NOT NULL,
    report_hash_algorithm   VARCHAR(20)     NOT NULL DEFAULT 'SHA-256',
    generated_by            UUID            NOT NULL
                            REFERENCES investigators(id)
                            ON DELETE RESTRICT,
    reviewed_by             UUID            NULL
                            REFERENCES investigators(id)
                            ON DELETE SET NULL,
    reviewed_at             TIMESTAMPTZ     NULL,
    is_court_ready          BOOLEAN         NOT NULL DEFAULT FALSE,
    court_ready_certified_by UUID           NULL
                            REFERENCES investigators(id)
                            ON DELETE SET NULL,
    court_ready_at          TIMESTAMPTZ     NULL,
    covers_hex_analysis     BOOLEAN         NOT NULL DEFAULT FALSE,
    covers_ai_analysis      BOOLEAN         NOT NULL DEFAULT FALSE,
    covers_chain_of_custody BOOLEAN         NOT NULL DEFAULT FALSE,
    generation_notes        TEXT            NULL,
    generated_at            TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_report_hash_length
        CHECK (length(report_hash) = 64),
    CONSTRAINT chk_court_ready_requires_certification
        CHECK (
            (is_court_ready = FALSE) OR
            (is_court_ready = TRUE AND court_ready_certified_by IS NOT NULL
             AND court_ready_at IS NOT NULL)
        )
);

CREATE TABLE system_audit_log (
    id                      UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    event_category          audit_event_category    NOT NULL,
    event_action            VARCHAR(200)    NOT NULL,
    event_description       TEXT            NULL,
    investigator_id         UUID            NULL
                            REFERENCES investigators(id)
                            ON DELETE SET NULL,
    ip_address              INET            NULL,
    user_agent              TEXT            NULL,
    request_id              UUID            NULL,
    session_id              VARCHAR(255)    NULL,
    http_method             VARCHAR(10)     NULL
                            CHECK (http_method IN ('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS')),
    endpoint_path           VARCHAR(1000)   NULL,
    response_status_code    SMALLINT        NULL
                            CHECK (response_status_code BETWEEN 100 AND 599),
    related_case_id         UUID            NULL,
    related_submission_id   UUID            NULL,
    success                 BOOLEAN         NOT NULL DEFAULT TRUE,
    error_code              VARCHAR(100)    NULL,
    error_message           TEXT            NULL,
    metadata_json           JSONB           NULL,
    occurred_at             TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- SECTION 6: INDEXES
-- =============================================================================

CREATE INDEX idx_investigators_email         ON investigators (email);
CREATE INDEX idx_investigators_role          ON investigators (role);
CREATE INDEX idx_investigators_is_active     ON investigators (is_active);

CREATE INDEX idx_cases_case_reference        ON cases (case_reference);
CREATE INDEX idx_cases_lead_investigator     ON cases (lead_investigator_id);
CREATE INDEX idx_cases_status               ON cases (status);
CREATE INDEX idx_cases_created_at           ON cases (created_at);

CREATE INDEX idx_submissions_case_id         ON file_submissions (case_id);
CREATE INDEX idx_submissions_submitted_by    ON file_submissions (submitted_by);
CREATE INDEX idx_submissions_sha256          ON file_submissions (sha256_hash);
CREATE INDEX idx_submissions_ingestion_ts    ON file_submissions (ingestion_timestamp);
CREATE INDEX idx_submissions_mime_declared   ON file_submissions (mime_type_declared);
CREATE INDEX idx_submissions_mime_detected   ON file_submissions (mime_type_detected);

CREATE INDEX idx_magic_hex_signature         ON magic_byte_signatures (hex_signature);
CREATE INDEX idx_magic_mime_type             ON magic_byte_signatures (mime_type);
CREATE INDEX idx_magic_threat_relevance      ON magic_byte_signatures (threat_relevance);
CREATE INDEX idx_magic_is_active             ON magic_byte_signatures (is_active);

CREATE INDEX idx_hex_submission_id           ON hex_analysis_results (submission_id);
CREATE INDEX idx_hex_mime_spoof              ON hex_analysis_results (mime_spoof_detected);
CREATE INDEX idx_hex_entropy_verdict         ON hex_analysis_results (entropy_verdict);
CREATE INDEX idx_hex_overall_risk            ON hex_analysis_results (overall_risk_level);
CREATE INDEX idx_hex_analyzed_at             ON hex_analysis_results (analyzed_at);

CREATE INDEX idx_ai_submission_id            ON ai_media_analysis_results (submission_id);
CREATE INDEX idx_ai_verdict                  ON ai_media_analysis_results (verdict);
CREATE INDEX idx_ai_media_type               ON ai_media_analysis_results (media_type);
CREATE INDEX idx_ai_analyzed_at              ON ai_media_analysis_results (analyzed_at);

CREATE INDEX idx_frame_ai_analysis_id        ON ai_analysis_frame_details (ai_analysis_id);
CREATE INDEX idx_frame_is_flagged            ON ai_analysis_frame_details (is_flagged);
CREATE INDEX idx_frame_anomaly_score         ON ai_analysis_frame_details (anomaly_score);

CREATE INDEX idx_custody_case_id             ON chain_of_custody_events (case_id);
CREATE INDEX idx_custody_submission_id       ON chain_of_custody_events (submission_id);
CREATE INDEX idx_custody_actor_id            ON chain_of_custody_events (actor_id);
CREATE INDEX idx_custody_event_type          ON chain_of_custody_events (event_type);
CREATE INDEX idx_custody_event_timestamp     ON chain_of_custody_events (event_timestamp);
CREATE INDEX idx_custody_sequence            ON chain_of_custody_events (submission_id, event_sequence);

CREATE INDEX idx_reports_submission_id       ON forensic_reports (submission_id);
CREATE INDEX idx_reports_case_id             ON forensic_reports (case_id);
CREATE INDEX idx_reports_generated_by        ON forensic_reports (generated_by);
CREATE INDEX idx_reports_is_court_ready      ON forensic_reports (is_court_ready);
CREATE INDEX idx_reports_generated_at        ON forensic_reports (generated_at);

CREATE INDEX idx_audit_investigator_id       ON system_audit_log (investigator_id);
CREATE INDEX idx_audit_event_category        ON system_audit_log (event_category);
CREATE INDEX idx_audit_ip_address            ON system_audit_log (ip_address);
CREATE INDEX idx_audit_request_id            ON system_audit_log (request_id);
CREATE INDEX idx_audit_occurred_at           ON system_audit_log (occurred_at);
CREATE INDEX idx_audit_related_case          ON system_audit_log (related_case_id);
CREATE INDEX idx_audit_success               ON system_audit_log (success);

-- =============================================================================
-- SECTION 7: IMMUTABILITY RULES
-- =============================================================================

CREATE RULE no_update_custody AS
    ON UPDATE TO chain_of_custody_events
    DO INSTEAD NOTHING;

CREATE RULE no_delete_custody AS
    ON DELETE TO chain_of_custody_events
    DO INSTEAD NOTHING;

CREATE RULE no_update_audit AS
    ON UPDATE TO system_audit_log
    DO INSTEAD NOTHING;

CREATE RULE no_delete_audit AS
    ON DELETE TO system_audit_log
    DO INSTEAD NOTHING;

-- =============================================================================
-- SECTION 8: SCHEMA VERSION TRACKING
-- =============================================================================

CREATE TABLE schema_migrations (
    id              SERIAL          PRIMARY KEY,
    version         VARCHAR(20)     NOT NULL UNIQUE,
    description     TEXT            NOT NULL,
    applied_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    checksum        CHAR(64)        NULL
);

INSERT INTO schema_migrations (version, description)
VALUES (
    '1.0.0',
    'Initial HexShield AI schema: investigators, cases, file_submissions, magic_byte_signatures, hex_analysis_results, ai_media_analysis_results, ai_analysis_frame_details, chain_of_custody_events, forensic_reports, system_audit_log.'
);