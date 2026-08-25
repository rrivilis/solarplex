-- 029's own doc comment says unlinking the source session "does not retract
-- or invalidate the copy already made" — but session_link_id's FK had no
-- ON DELETE clause, which defaults to NO ACTION/RESTRICT in Postgres. That
-- made DELETE FROM session_links fail outright with a foreign key violation
-- the moment any artifact had ever been imported through that link, instead
-- of just detaching the (purely informational) audit-note pointer.
--
-- The import row is a completed, independent receipt — the artifact copy,
-- content hash, publisher, and importer are unaffected by the link going
-- away. Only session_link_id itself (which link this flowed through, for
-- display) needs to null out.
ALTER TABLE artifact_imports
    DROP CONSTRAINT artifact_imports_session_link_id_fkey,
    ADD CONSTRAINT artifact_imports_session_link_id_fkey
        FOREIGN KEY (session_link_id) REFERENCES session_links(id) ON DELETE SET NULL;
