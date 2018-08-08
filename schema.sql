--
-- Note: This schema is an extract from the Django models of the new (not yet
-- released) version of PrivacyScore.
-- 
BEGIN;

CREATE TABLE base_author (
    id serial NOT NULL PRIMARY KEY,
    name character varying(200) NOT NULL,
    email character varying(254)
);

CREATE UNIQUE INDEX base_author_uniq ON base_author(lower(name), lower(email));

CREATE TABLE sites_site (
    id character varying(40) NOT NULL PRIMARY KEY,
    url text NOT NULL,
    is_private boolean NOT NULL,
    latest_scan_id integer,
    date_created timestamp with time zone NOT NULL,
    num_views integer NOT NULL,
    CONSTRAINT sites_site_num_views_check CHECK ((num_views >= 0))
);

CREATE INDEX sites_site_latest_scan ON sites_site(latest_scan_id);

CREATE TABLE sites_sitelist (
    id character varying(40) NOT NULL PRIMARY KEY,
    edit_token character varying(40) NOT NULL,
    name character varying(200) NOT NULL,
    description text NOT NULL,
    is_private boolean NOT NULL,
    date_created timestamp with time zone NOT NULL,
    num_views integer NOT NULL,
    author_id integer NOT NULL,
    latest_scan_id integer,
    CONSTRAINT sites_sitelist_num_views_check CHECK ((num_views >= 0))
);

CREATE INDEX sites_sitelist_latest_scan ON sites_sitelist(latest_scan_id);

CREATE TABLE sites_sitelist_sites (
    id serial NOT NULL PRIMARY KEY,
    sitelist_id character varying(40) NOT NULL REFERENCES sites_sitelist(id),
    site_id character varying(40) NOT NULL REFERENCES sites_site(id)
);

CREATE UNIQUE INDEX sites_sitelist_sites_uniq ON sites_sitelist_sites(sitelist_id, site_id);
CREATE INDEX sites_sitelist_sites_site ON sites_sitelist_sites(site_id);

CREATE TABLE scanner_scan (
    id serial NOT NULL PRIMARY KEY,
    time_started timestamp with time zone NOT NULL,
    time_finished timestamp with time zone,
    result jsonb,
    is_latest boolean NOT NULL,
    site_id character varying(40) NOT NULL REFERENCES sites_site(id)
);

CREATE INDEX latest_scans ON scanner_scan USING btree (is_latest) WHERE is_latest;
CREATE INDEX scanner_scan_site ON scanner_scan(site_id);

CREATE TABLE scanner_scanjob (
    id serial NOT NULL PRIMARY KEY,
    scan_module character varying(80) NOT NULL,
    priority integer NOT NULL,
    dependency_order integer NOT NULL,
    scan_id integer NOT NULL REFERENCES scanner_scan(id),
    not_before timestamp with time zone
);

CREATE INDEX scanner_scanjob_scan ON scanner_scanjob(scan_id);

CREATE TABLE scanner_scaninfo (
    id serial NOT NULL PRIMARY KEY,
    scan_module character varying(80) NOT NULL,
    scan_host character varying(80),
    time_started timestamp with time zone,
    time_finished timestamp with time zone,
    scan_id integer NOT NULL REFERENCES scanner_scan(id),
    num_tries integer NOT NULL
);

CREATE INDEX scanner_scaninfo_scan ON scanner_scaninfo(scan_id);

CREATE TABLE scanner_logentry (
    id serial NOT NULL PRIMARY KEY,
    level integer NOT NULL,
    message text,
    scan_host character varying(80) NOT NULL,
    scan_module character varying(80) NOT NULL,
    scan_id integer NOT NULL REFERENCES scanner_scan(id),
    time_created timestamp with time zone NOT NULL
);

CREATE INDEX scanner_logentry_scan ON scanner_logentry(scan_id);

-- Not used yet. Will be filled by PrivacyScore and not by PrivacyScanner
CREATE TABLE scanner_fileresult (
    id integer NOT NULL,
    identifier character varying(80) NOT NULL,
    result character varying(100) NOT NULL,
    scan_id integer NOT NULL REFERENCES scanner_scan(id)
);

CREATE INDEX scanner_fileresult_scan ON scanner_fileresult(scan_id);

-- Not used yet. Will be filled by PrivacyScore and not by PrivacyScanner
CREATE TABLE scanner_debugfile (
    id serial NOT NULL PRIMARY KEY,
    identifier character varying(80) NOT NULL,
    "offset" integer NOT NULL,
    uncompressed_size integer NOT NULL,
    scan_id integer NOT NULL REFERENCES scanner_scan(id),
    CONSTRAINT scanner_debugfile_offset_check CHECK (("offset" >= 0)),
    CONSTRAINT scanner_debugfile_uncompressed_size_check CHECK ((uncompressed_size >= 0))
);

CREATE INDEX scanner_debugfile_scan ON scanner_debugfile(scan_id);

CREATE FUNCTION update_scan_info() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
        DECLARE
          old_max timestamp;
          new_scan RECORD;
        BEGIN
          IF (TG_OP = 'DELETE') THEN
            SELECT id, time_finished FROM scanner_scan
              WHERE site_id = OLD.site_id AND time_finished IS NOT NULL
              ORDER BY time_finished INTO new_scan;
            IF NOT FOUND THEN
              UPDATE sites_site SET latest_scan_id = NULL WHERE id=OLD.site_id;
              UPDATE sites_sitelist SET latest_scan_id=NULL
                WHERE id IN (SELECT sitelist_id FROM sites_sitelist_sites WHERE site_id = OLD.site_id);
            ELSE
              UPDATE sites_site SET latest_scan_id = new_scan.id WHERE id=OLD.site_id;
              UPDATE scanner_scan SET is_latest = 't' WHERE id = new_scan.id;
              UPDATE sites_sitelist SET latest_scan_id=new_scan.id
                WHERE id IN (SELECT sitelist_id FROM sites_sitelist_sites WHERE site_id = OLD.site_id);
            END IF;
            RETURN OLD;
          ELSIF (TG_OP = 'INSERT' OR TG_OP = 'UPDATE') THEN
            IF NEW.time_finished IS NULL THEN
              RETURN NEW;
            END IF;
            SELECT MAX(time_finished) FROM scanner_scan WHERE site_id = NEW.site_id INTO old_max;
            IF old_max IS NULL OR NEW.time_finished >= old_max THEN
                UPDATE sites_site SET latest_scan_id = NEW.id WHERE id=NEW.site_id;
                UPDATE scanner_scan SET is_latest = 'f' WHERE site_id=NEW.site_id AND is_latest = 't';
                UPDATE scanner_scan SET is_latest = 't' WHERE id = NEW.id;
                UPDATE sites_sitelist SET latest_scan_id=NEW.id
                    WHERE id IN (SELECT sitelist_id FROM sites_sitelist_sites WHERE site_id = NEW.site_id);
            END IF;
            RETURN NEW;
          END IF;
        END
        $$;

CREATE TRIGGER scan_update AFTER INSERT OR DELETE OR UPDATE OF time_finished ON scanner_scan FOR EACH ROW EXECUTE PROCEDURE update_scan_info();

-- TODO: Add trigger function which sets the scanner_scan(scan_finished) field.

COMMIT;
