-- Artifact family graph: YARA-rule / TLSH-cluster families
CREATE TABLE artifact_families (
    id             TEXT        PRIMARY KEY,
    name           TEXT        NOT NULL,
    verdict        TEXT        NOT NULL DEFAULT 'unknown',  -- 'benign' | 'suspicious' | 'malicious' | 'unknown'
    tlsh_centroid  TEXT,
    yara_rules     TEXT[]      NOT NULL DEFAULT '{}',
    member_count   INTEGER     NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Per-content-hash prevalence + scan results
CREATE TABLE artifact_hashes (
    sha256           TEXT        PRIMARY KEY,
    tlsh             TEXT,
    family_id        TEXT        REFERENCES artifact_families(id),
    first_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    seen_count       INTEGER     NOT NULL DEFAULT 1,
    yara_matches     TEXT[]      NOT NULL DEFAULT '{}',
    verdict_override TEXT,       -- manual analyst override
    verdict_source   TEXT        -- 'yara' | 'cluster' | 'manual'
);

CREATE INDEX artifact_hashes_family_id_idx  ON artifact_hashes (family_id);
CREATE INDEX artifact_hashes_seen_count_idx ON artifact_hashes (seen_count);
