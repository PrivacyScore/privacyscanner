import logging
import multiprocessing
import os
import signal
import sys
import tempfile
import time
import queue
import socket
from datetime import datetime

import psycopg2

from privacyscanner.filehandlers import NoOpFileHandler
from privacyscanner.jobqueue import JobQueue
from privacyscanner.result import Result
from privacyscanner.scanmodules import load_modules
from privacyscanner.loghandlers import WorkerQueueHandler, ScanStreamHandler


_JOB_STARTED_QUERY = """
UPDATE scanner_scaninfo
SET scan_host = %s,
    time_started = %s,
    num_tries = num_tries + 1
WHERE scan_id = %s AND scan_module = %s
"""

_JOB_FINISHED_QUERY = """
UPDATE scanner_scaninfo
SET time_finished = %s
WHERE scan_id = %s AND scan_module = %s
"""

_JOB_FAILED_QUERY = """
UPDATE scanner_scaninfo
SET scan_host = NULL,
    time_started = NULL
WHERE scan_id = %s AND scan_module = %s
"""

_LOG_QUERY = """
INSERT INTO scanner_logentry (scan_id, scan_module, scan_host, time_created, level, message)
VALUES (%s, %s, %s, %s, %s, %s)
"""


class WorkerInfo:
    def __init__(self, pid, stop_event):
        self.pid = pid
        self.stop_event = stop_event
        self.scan_id = None
        self.scan_module = None
        self._heartbeat = None
        self._last_execution_time = None
        self.ping()

    def ping(self):
        self._heartbeat = time.time()

    def notify_job_started(self, scan_id, scan_module):
        self.scan_id = scan_id
        self.scan_module = scan_module
        self._last_execution_time = time.time()

    def notify_job_finished(self):
        self.scan_id = None
        self.scan_module = None

    notify_job_failed = notify_job_finished

    def get_execution_time(self):
        if self._last_execution_time is None:
            return 0
        return max(time.time() - self._last_execution_time, 0)

    def stop(self):
        self.stop_event.set()


class WorkerMaster:
    def __init__(self, db_dsn, scan_module_list, scan_module_options=None,
                 num_workers=2, max_executions=100, max_execution_times=None):
        self.name = socket.gethostname()
        self._db_dsn = db_dsn
        self.scan_module_list = scan_module_list
        if scan_module_options is None:
            scan_module_options = {}
        self.scan_module_options = scan_module_options
        self.num_workers = num_workers
        self.max_executions = max_executions
        if max_execution_times is None:
            max_execution_times = {None: None}
        self.max_execution_times = max_execution_times
        self.max_execution_time = max_execution_times.get(None)
        self._workers = {}
        self._terminated_workers = set()
        self._running = False
        self._force_stop = False
        self._queue = multiprocessing.Queue()
        self._conn = None
        self._connect()

    def start(self):
        signal.signal(signal.SIGCHLD, self._handle_signal_child)
        signal.signal(signal.SIGINT, self._handle_signal_stop)
        signal.signal(signal.SIGTERM, self._handle_signal_stop)
        self._running = True
        while self._running:
            self._fork_workers()
            self._process_queue()
            self._check_hanging()
            self._remove_workers()
            time.sleep(0.25)
        print('\nGently asking workers to stop ...')
        for pid, worker_info in self._workers.items():
            worker_info.stop()
        while not self._force_stop and self._workers:
            self._remove_workers()
            time.sleep(0.25)
        if self._workers:
            print('Forcefully killing workers ...')
            for pid in list(self._workers.keys()):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    del self._workers[pid]
            for pid in self._workers.keys():
                os.waitpid(pid, 0)
        print('All workers stopped. Shutting down ...')

    def stop(self):
        if self._running:
            self._running = False
        else:
            self._force_stop = True

    def _connect(self):
        if self._conn is None or self._conn.closed:
            self._conn = psycopg2.connect(self._db_dsn)

    def _clear_signals(self):
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)

    def _fork_workers(self):
        ppid = os.getpid()
        for i in range(self.num_workers - len(self._workers)):
            stop_event = multiprocessing.Event()
            pid = os.fork()
            if pid == 0:
                self._clear_signals()
                worker = Worker(ppid, self._db_dsn, self.scan_module_list,
                                self.scan_module_options, self.max_executions,
                                self._queue, stop_event)
                worker.run()
                sys.exit(0)
            else:
                self._workers[pid] = WorkerInfo(pid, stop_event)

    def _process_queue(self):
        while True:
            try:
                pid, action, args = self._queue.get_nowait()
                worker_info = self._workers[pid]
                worker_info.ping()
                if action == 'job_started':
                    scan_id, scan_module_name, time_started, num_tries = args
                    worker_info.notify_job_started(scan_id, scan_module_name)
                    self._event_job_started(scan_id, scan_module_name, time_started)
                elif action == 'job_finished':
                    self._event_job_finished(
                        worker_info.scan_id, worker_info.scan_module, time_finished=args[0])
                    worker_info.notify_job_finished()
                elif action == 'job_failed':
                    self._event_job_failed(worker_info.scan_id, worker_info.scan_module)
                    worker_info.notify_job_failed()
                elif action == 'log':
                    log_time, level, message = args
                    self._event_job_log(worker_info.scan_id, worker_info.scan_module,
                                        log_time, level, message)
                elif action == 'add_file':
                    pass
                elif action == 'add_debug_file':
                    pass

            except queue.Empty:
                break

    def _event_job_started(self, scan_id, scan_module_name, time_started):
        params = (self.name, time_started, scan_id, scan_module_name)
        self._execute_sql_autocommit(_JOB_STARTED_QUERY, params)

    def _event_job_finished(self, scan_id, scan_module_name, time_finished):
        params = (time_finished, scan_id, scan_module_name)
        self._execute_sql_autocommit(_JOB_FINISHED_QUERY, params)

    def _event_job_failed(self, scan_id, scan_module_name):
        params = (scan_id, scan_module_name)
        self._execute_sql_autocommit(_JOB_FAILED_QUERY, params)

    def _event_job_log(self, scan_id, scan_module_name, log_time, level, message):
        log_time = datetime.fromtimestamp(log_time)
        params = (scan_id, scan_module_name, self.name, log_time, level, message)
        self._execute_sql_autocommit(_LOG_QUERY, params)

    def _execute_sql_autocommit(self, query, params):
        self._connect()
        with self._conn.cursor() as c:
            c.execute(query, params)
        self._conn.commit()

    def _check_hanging(self):
        for pid, worker_info in self._workers.items():
            max_execution_time = self.max_execution_times.get(
                worker_info.scan_module, self.max_execution_time)
            if max_execution_time is None:
                continue
            if worker_info.get_execution_time() > max_execution_time:
                worker_info.notify_job_failed()
                self._event_job_failed(worker_info.scan_id, worker_info.scan_module)
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    self._terminated_workers.add(pid)

    def _remove_workers(self):
        for pid in self._terminated_workers:
            del self._workers[pid]
        self._terminated_workers.clear()

    def _handle_signal_child(self, signum, frame):
        assert signum == signal.SIGCHLD
        while True:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
                if pid not in self._workers:
                    continue
                if os.WIFSIGNALED(status) or os.WIFEXITED(status):
                    # Do not remove it directly from workers because there
                    # might be events for that worker that still have to be
                    # processed.
                    self._terminated_workers.add(pid)
            except ChildProcessError:
                return

    def _handle_signal_stop(self, signum, frame):
        assert signum in (signal.SIGINT, signal.SIGTERM)
        self.stop()


class Worker:
    def __init__(self, ppid, db_dsn, scan_module_list, scan_module_options,
                 max_executions, queue, stop_event):
        self._pid = os.getpid()
        self._ppid = ppid
        self._max_executions = max_executions
        self._queue = queue
        self._stop_event = stop_event
        self._old_sigterm = signal.SIG_DFL
        self._old_sigint = signal.SIG_DFL
        self._job_queue = JobQueue(db_dsn, load_modules(scan_module_list),
                                   scan_module_options)

    def run(self):
        while self._max_executions > 0:
            job = self._job_queue.get_job()
            start_info = (job.scan_id, job.scan_module.name, datetime.today(), job.num_tries)
            self._notify_master('job_started', start_info)
            result = Result(job.current_result, NoOpFileHandler())
            logger = logging.Logger(job.scan_module.name)
            logger.addHandler(WorkerQueueHandler(self._pid, self._queue))
            logger.addHandler(ScanStreamHandler())
            with tempfile.TemporaryDirectory() as temp_dir:
                old_cwd = os.getcwd()
                os.chdir(temp_dir)
                try:
                    job.scan_module.scan_site(result, logger, job.options)
                except Exception:
                    logger.exception('Scan module `{}` failed.'.format(job.scan_module.name))
                    self._job_queue.report_failure()
                    self._notify_master('job_failed', (datetime.today(), ))
                else:
                    self._job_queue.report_result(result.get_updates())
                    self._notify_master('job_finished', (datetime.today(), ))
                finally:
                    os.chdir(old_cwd)
            self._max_executions -= 1

            # Stop if our master died.
            if self._ppid != os.getppid():
                break

            # Our master asked us to stop. We must obey.
            if self._stop_event.is_set():
                break

    def _notify_master(self, action, args):
        self._queue.put((self._pid, action, args))
