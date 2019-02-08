import enum
import json
import subprocess
import tempfile
from pathlib import Path


class TestsslshFailed(Exception):
    def __init__(self, exit_code, *args):
        self.exit_code = exit_code
        super().__init__(*args)


class TestsslshFailedPartially(TestsslshFailed):
    def __init__(self, exit_code, partial_result, *args):
        self.partial_result = partial_result
        super().__init__(exit_code, *args)


class Parameter(enum.Enum):
    STARTTLS = '-t'
    PROTOCOLS = '-p'
    SERVER_DEFAULTS = '-S'
    SERVER_PREFERENCE = '-P'
    STANDARD_CIPHERS = '-s'
    CHECK_FORWARD_SECRECY = '-f'
    FAST = '--fast'
    IP = '--ip'
    SNEAKY = '--sneaky'
    # PHONE_OUT allows OCSP querying and CRL download
    PHONE_OUT = '--phone-out'
    JSONFILE = '--jsonfile'
    HTMLFILE = '--htmlfile'

    VULN_ALL = '-U'
    VULN_HEARTBLEED = '-H'
    VULN_CCS_INJECTION = '-I'
    VULN_TICKETBLEED = '-T'
    VULN_ROBOT = '-BB'
    VULN_CRIME = '-C'
    VULN_BREACH = '-B'
    VULN_POODLE = '-O'
    VULN_TLS_FALLBACK = '-Z'
    VULN_RENEGOTIATION = '-R'
    VULN_SWEET32 = '-W'
    VULN_BEAST = '-A'
    VULN_LUCKY13 = '-L'
    VULN_FREAK = '-F'
    VULN_LOGJAM = '-J'
    VULN_DROWN = '-D'
    VULN_RC4 = '-4'


class TestsslshScanner:
    def __init__(self, install_dir):
        self._install_dir = Path(install_dir)
        self.parameters = []
        self.environment = {
            'USLEEP_SND': '0.1', # 0.5
            'USLEEP_REC': '0.1',
            'TESTSSL_INSTALL_DIR': str(self._install_dir)
        }
        self.result = None

    def add_parameters(self, *parameters):
        for parameter in parameters:
            if isinstance(parameter, Parameter):
                parameter = parameter.value
            self.parameters.append(parameter)

    def scan(self, target_url):
        executable = self._install_dir / 'testssl.sh'
        command = [str(executable)] + self.parameters
        with tempfile.NamedTemporaryFile() as f:
            command += (Parameter.JSONFILE.value, f.name, target_url)
            p = subprocess.run(command,
                               stderr=subprocess.PIPE,
                               stdout=subprocess.DEVNULL,
                               env=self.environment,
                               check=False,
                               encoding='utf-8',
                               errors='replace')
            f.seek(0)
            try:
                scan_list = json.load(f)
            except json.JSONDecodeError:
                raise TestsslshFailed(-1000, 'JSON decode failed.')

        result = {}
        for entry in scan_list:
            if 'id' not in entry:
                continue
            result[entry['id']] = entry

        # Check if we actually have any results. This means that we check
        # whether there are keys that are not engine_problem or scanTime,
        # which are available even if the host is not reachable.
        min_length = 1
        for no_result_key in ('engine_problem', 'scanTime'):
            if no_result_key in result:
                min_length += 1
        if len(result) < min_length:
            result = None

        if not (0 <= p.returncode < 50):
            if result is not None:
                raise TestsslshFailedPartially(p.returncode, result, p.stderr)
            raise TestsslshFailed(p.returncode, p.stderr)

        return result
