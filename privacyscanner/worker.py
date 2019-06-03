import logging
import multiprocessing
import os
import signal
import socket
import tempfile
import time
from datetime import datetime
from multiprocessing.connection import wait

import psycopg2

from privacyscanner.exceptions import RetryScan, RescheduleLater
from privacyscanner.filehandlers import NoOpFileHandler
from privacyscanner.jobqueue import JobQueue
from privacyscanner.raven import has_raven, raven
from privacyscanner.result import Result
from privacyscanner.scanmeta import ScanMeta
from privacyscanner.scanmodules import load_modules
from privacyscanner.loghandlers import WorkerWritePipeHandler, ScanStreamHandler
from privacyscanner.utils import kill_everything


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
    def __init__(self, worker_id, process, read_pipe, stop_event, ack_event):
        self.id = worker_id
        self.process = process
        self.read_pipe = read_pipe
        self.stop_event = stop_event
        self.ack_event = ack_event
        self.scan_id = None
        self.scan_module = None
        self._heartbeat = None
        self._last_execution_time = None
        self.ping()

    @property
    def pid(self):
        return self.process.pid

    def ping(self):
        self._heartbeat = time.time()

    def ack(self):
        self.ack_event.set()

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

    def __str__(self):
        return '<{}/{} pid={}>'.format(self.scan_id, self.scan_module, self.pid)


class WorkerMaster:
    def __init__(self, db_dsn, scan_module_list, scan_module_options=None,
                 max_tries=3, num_workers=2, max_executions=100,
                 max_execution_times=None, raven_dsn=None):
        self.name = socket.gethostname()
        self._db_dsn = db_dsn
        self.scan_module_list = scan_module_list
        if scan_module_options is None:
            scan_module_options = {}
        self.scan_module_options = scan_module_options
        self.max_tries = max_tries
        self.num_workers = num_workers
        self.max_executions = max_executions
        if max_execution_times is None:
            max_execution_times = {None: None}
        self.max_execution_times = max_execution_times
        self.max_execution_time = max_execution_times.get(None)
        self._raven_dsn = raven_dsn
        self._workers = {}
        self._worker_ids = set(range(num_workers))
        self._terminated_worker_pids = set()
        self._running = False
        self._force_stop = False
        self._conn = None
        self._connect()

    def start(self):
        multiprocessing.set_start_method('spawn')
        signal.signal(signal.SIGINT, self._handle_signal_stop)
        signal.signal(signal.SIGTERM, self._handle_signal_stop)
        signal.signal(signal.SIGUSR1, self._handle_signal_usr1)
        self._running = True
        while self._running:
            self._start_workers()
            self._process_queue()
            self._check_hanging()
            self._remove_workers()
            time.sleep(0.25)
        print('\nGently asking workers to stop after their current job ...')
        for worker_info in self._workers.values():
            worker_info.stop()
        while not self._force_stop and self._workers:
            workers_str = self._get_running_workers_str()
            print('{} workers still alive: {}'.format(len(self._workers), workers_str))
            self._check_hanging()
            self._remove_workers()
            time.sleep(0.25)
        if self._workers:
            print('Forcefully killing workers ...')
            for worker_info in self._workers.values():
                kill_everything(worker_info.pid)
        print('All workers stopped. Shutting down ...')

    def stop(self):
        if self._running:
            self._running = False
        else:
            self._force_stop = True

    def _connect(self):
        if self._conn is None or self._conn.closed:
            self._conn = psycopg2.connect(self._db_dsn)

    def _start_workers(self):
        ppid = os.getpid()
        for i in range(self.num_workers - len(self._workers)):
            worker_id = self._worker_ids.pop()
            stop_event = multiprocessing.Event()
            ack_event = multiprocessing.Event()
            read_pipe, write_pipe = multiprocessing.Pipe(duplex=False)
            args = (worker_id, ppid, self._db_dsn, self.scan_module_list,
                    self.scan_module_options, self.max_tries, self.max_executions,
                    write_pipe, stop_event, ack_event, self._raven_dsn)
            process = WorkerProcess(target=_spawn_worker, args=args)
            process.start()
            worker_info = WorkerInfo(worker_id, process, read_pipe, stop_event, ack_event)
            self._workers[worker_info.pid] = worker_info

    def _process_queue(self):
        while True:
            pipes = [worker_info.read_pipe for worker_info in self._workers.values()
                     if worker_info.process.is_alive()]
            ready_pipes = wait(pipes, timeout=0.1)
            if not ready_pipes:
                break
            for read_pipe in ready_pipes:
                try:
                    event = read_pipe.recv()
                except EOFError:
                    continue
                self._process_queue_event(event)

    def _process_queue_event(self, event):
        pid, action, args = event
        worker_info = self._workers[pid]
        worker_info.ping()
        if action == 'job_started':
            scan_id, scan_module_name, time_started, num_tries = args
            self._event_job_started(scan_id, scan_module_name, time_started)
            worker_info.notify_job_started(scan_id, scan_module_name)
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
        worker_info.ack()

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
        while True:
            try:
                self._connect()
                with self._conn.cursor() as c:
                    c.execute(query, params)
                self._conn.commit()
                break
            except psycopg2.OperationalError:
                print('Database operational error. Retrying after 10 seconds.')
                time.sleep(10)

    def _check_hanging(self):
        for worker_info in self._workers.values():
            max_execution_time = self.max_execution_times.get(
                worker_info.scan_module, self.max_execution_time)
            if max_execution_time is None:
                continue
            if worker_info.get_execution_time() > max_execution_time:
                worker_info.notify_job_failed()
                self._event_job_failed(worker_info.scan_id, worker_info.scan_module)
                kill_everything(worker_info.pid)
                self._terminated_worker_pids.add(worker_info.pid)

    def _remove_workers(self):
        for worker_info in self._workers.values():
            if not worker_info.process.is_alive():
                self._terminated_worker_pids.add(worker_info.pid)
        for pid in self._terminated_worker_pids:
            self._worker_ids.add(self._workers[pid].id)
            del self._workers[pid]
        self._terminated_worker_pids.clear()

    def _handle_signal_stop(self, signum, frame):
        assert signum in (signal.SIGINT, signal.SIGTERM)
        self.stop()

    def _handle_signal_usr1(self, signum, frame):
        assert signum == signal.SIGUSR1
        print('Running workers: {}'.format(self._get_running_workers_str()))

    def _get_running_workers_str(self):
        return ' '.join(str(worker_info) for worker_info in self._workers.values())


def _spawn_worker(*args, **kwargs):
    w = Worker(*args, **kwargs)
    w.run()


class Worker:
    def __init__(self, worker_id, ppid, db_dsn, scan_module_list, scan_module_options,
                 max_tries, max_executions, write_pipe, stop_event, ack_event,
                 raven_dsn):
        self._id = worker_id
        self._pid = os.getpid()
        self._ppid = ppid
        self._max_executions = max_executions
        self._write_pipe = write_pipe
        self._stop_event = stop_event
        self._ack_event = ack_event
        self._old_sigterm = signal.SIG_DFL
        self._old_sigint = signal.SIG_DFL
        self._raven_client = None
        if has_raven and raven_dsn:
            self._raven_client = raven.Client(raven_dsn)
        scan_modules = load_modules(scan_module_list, scan_module_options)
        self._job_queue = JobQueue(db_dsn, scan_modules, max_tries)

    def run(self):
        while self._max_executions > 0:
            # Stop if our master died.
            if self._ppid != os.getppid():
                break

            # Our master asked us to stop. We must obey.
            if self._stop_event.is_set():
                break
            job = self._job_queue.get_job_nowait()
            if job is None:
                time.sleep(1)
                continue
            start_info = (job.scan_id, job.scan_module.name, datetime.today(), job.num_tries)
            self._notify_master('job_started', start_info)
            result = Result(job.current_result, NoOpFileHandler())
            logger = logging.Logger(job.scan_module.name)
            logger.addHandler(WorkerWritePipeHandler(self._pid, self._write_pipe))
            logger.addHandler(ScanStreamHandler())
            scan_meta = ScanMeta(worker_id=self._id, num_tries=job.num_tries)
            with tempfile.TemporaryDirectory() as temp_dir:
                old_cwd = os.getcwd()
                os.chdir(temp_dir)
                try:
                    job.scan_module.logger = logger
                    job.scan_module.scan_site(result, scan_meta)
                except RetryScan:
                    self._job_queue.report_failure()
                    self._notify_master('job_failed', (datetime.today(),))
                except RescheduleLater as e:
                    self._job_queue.reschedule(e.not_before)
                    self._job_queue.report_result(result.get_updates())
                    self._notify_master('job_finished', (datetime.today(),))
                except Exception:
                    logger.exception('Scan module `%s` failed.', job.scan_module.name)
                    self._job_queue.report_failure()
                    self._notify_master('job_failed', (datetime.today(),))
                    if self._raven_client:
                        self._raven_client.captureException(tags={
                            'scan_id': job.scan_id,
                            'scan_module_name': job.scan_module.name
                        }, extra={'result': result.get_results()})
                else:
                    self._job_queue.report_result(result.get_updates())
                    self._notify_master('job_finished', (datetime.today(),))
                finally:
                    os.chdir(old_cwd)
                    kill_everything(self._pid, only_children=True)
            self._max_executions -= 1
        kill_everything(self._pid)

    def _notify_master(self, action, args):
        self._write_pipe.send((self._pid, action, args))
        self._ack_event.wait()
        self._ack_event.clear()


class WorkerProcess(multiprocessing.Process):
    def run(self):
        # We do not want our worker to receive the signals our parent (master)
        # gets. Therefore move it into an own process group.
        os.setpgid(0, 0)
        super().run()
