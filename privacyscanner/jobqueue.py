from typing import NamedTuple

import psycopg2
from psycopg2.extras import Json
import time


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
  ) AND sj1.scan_module IN(%s)
    AND si.scan_id = sj1.scan_id
    AND si.scan_module = sj1.scan_module
    AND si.num_tries < 3
  ORDER BY sj1.priority DESC, sj1.scan_id, sj1.dependency_order
  FOR UPDATE OF sj1 SKIP LOCKED
  LIMIT 1
)
DELETE FROM scanner_scanjob
WHERE id = (SELECT id FROM job)
RETURNING id, scan_id, scan_module, (SELECT num_tries FROM job) AS num_tries
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


class Job(NamedTuple):
    scan_id: int
    scan_module: object
    options: dict
    current_result: dict
    num_tries: int


class JobQueue:
    def __init__(self, dsn, scan_modules, scan_module_options):
        self._dsn = dsn
        self._scan_modules = scan_modules
        self._scan_module_options = scan_module_options
        self._available_modules = tuple(self._scan_modules.keys())
        self._scan_id = None
        self._conn = None
        self._connect()

    def get_job(self):
        while True:
            job = self._get_job_nowait()
            if job:
                return job
            time.sleep(1)

    def report_result(self, updates):
        assert self._scan_id is not None
        with self._conn.cursor() as c:
            c.execute(_UPDATE_RESULT_QUERY, (Json(updates), self._scan_id))
        self._scan_id = None
        self._conn.commit()

    def report_failure(self):
        assert self._scan_id is not None
        self._scan_id = None
        self._conn.rollback()

    def _connect(self):
        self._conn = psycopg2.connect(self._dsn)

    def _get_job_nowait(self):
        assert self._scan_id is None
        if self._conn.closed:
            self._connect()
        with self._conn.cursor() as c:
            c.execute(_FETCH_JOB_QUERY, (self._available_modules, ))
            job = c.fetchone()
            if job:
                job_id, scan_id, scan_module_name, num_tries = job
                scan_module = self._scan_modules[scan_module_name]
                options = self._scan_module_options.get(scan_module_name, {})
                if scan_module.required_keys:
                    c.execute(_FETCH_RESULT_QUERY, (scan_id, tuple(scan_module.required_keys)))
                    result = dict(c.fetchall())
                else:
                    result = {}
                self._scan_id = scan_id
                return Job(scan_id, scan_module, options, result, num_tries)
