from typing import NamedTuple

import psycopg2
from psycopg2.extras import Json


_FETCH_JOB_QUERY = """
WITH job AS (
  SELECT sj1.id, si.num_tries
  FROM scanner_scanjob AS sj1,
       scanner_scaninfo AS si
  WHERE NOT EXISTS ( -- Make sure our dependencies are processed first
    SELECT id
    FROM scanner_scanjob AS sj2
    WHERE sj2.dependency_order < sj1.dependency_order AND
          sj2.scan_id = sj1.scan_id
  ) AND sj1.scan_module IN %s
    AND si.scan_id = sj1.scan_id
    AND si.scan_module = sj1.scan_module
    AND si.num_tries < %s
    AND (sj1.not_before IS NULL OR sj1.not_before <= NOW())
  ORDER BY sj1.priority DESC, sj1.scan_id, sj1.dependency_order
  FOR UPDATE OF sj1 SKIP LOCKED
  LIMIT 1
)
DELETE FROM scanner_scanjob
WHERE id = (SELECT id FROM job)
RETURNING id, scan_id, scan_module, (SELECT num_tries FROM job) AS num_tries, dependency_order, priority
"""

_FETCH_RESULT_QUERY = """
SELECT (kv).key, (kv).value
FROM (
  SELECT jsonb_each(result) AS kv
  FROM scanner_scan
  WHERE id = %s
) AS s
WHERE (kv).key IN %s
"""

_UPDATE_RESULT_QUERY = """
UPDATE scanner_scan
SET result = result || %s::jsonb
WHERE id = %s
"""

_RESCHEDULE_JOB_QUERY = """
INSERT INTO scanner_scanjob
(scan_module, priority, dependency_order, scan_id, not_before)
VALUES (%s, %s, %s, %s, %s)
"""

_INCREASE_TRIES_QUERY = """
UPDATE scanner_scaninfo
SET num_tries = GREATEST(0, num_tries - 1)
WHERE scan_id = %s AND scan_module = %s
"""

class Job(NamedTuple):
    scan_id: int
    scan_module: object
    current_result: dict
    num_tries: int
    dependency_order: int
    priority: int


class JobQueue:
    def __init__(self, dsn, scan_modules, max_tries):
        self._dsn = dsn
        self._scan_modules = scan_modules
        self._available_modules = tuple(self._scan_modules.keys())
        self._max_tries = max_tries
        self._last_job = None
        self._conn = None
        self._connect()

    def report_result(self, updates):
        assert self._last_job is not None
        with self._conn.cursor() as c:
            c.execute(_UPDATE_RESULT_QUERY, (Json(updates), self._last_job.scan_id))
        self._last_job = None
        self._conn.commit()

    def report_failure(self):
        assert self._last_job is not None
        self._last_job = None
        self._conn.rollback()

    def _connect(self):
        self._conn = psycopg2.connect(self._dsn)

    def get_job_nowait(self):
        assert self._last_job is None
        if self._conn.closed:
            self._connect()
        with self._conn.cursor() as c:
            c.execute(_FETCH_JOB_QUERY, (self._available_modules, self._max_tries))
            job = c.fetchone()
            if job:
                job_id, scan_id, scan_module_name, num_tries, dependency_order, priority = job
                scan_module = self._scan_modules[scan_module_name]
                if scan_module.required_keys:
                    c.execute(_FETCH_RESULT_QUERY, (scan_id, tuple(scan_module.required_keys)))
                    result = dict(c.fetchall())
                else:
                    result = {}
                job = Job(scan_id, scan_module, result, num_tries, dependency_order, priority)
                self._last_job = job
                return job

    def reschedule(self, not_before=None):
        assert self._last_job is not None
        with self._conn.cursor() as c:
            params = (self._last_job.scan_module.name, self._last_job.priority,
                      self._last_job.dependency_order, self._last_job.scan_id,
                      not_before)
            c.execute(_RESCHEDULE_JOB_QUERY, params)
            c.execute(_INCREASE_TRIES_QUERY, (self._last_job.scan_id,
                                              self._last_job.scan_module.name))
