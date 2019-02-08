import enum
import json
import subprocess
import tempfile
from pathlib import Path


class TestsslshFailed(Exception):
    def __init__(self, exit_code, msg):
        self.exit_code = exit_code
        super().__init__(msg)


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
            if not (0 <= p.returncode < 50):
                raise TestsslshFailed(p.returncode, p.stderr)
            f.seek(0)
            scan_list = json.load(f)
        result = {}
        for entry in scan_list:
            if 'id' not in entry:
                continue
            result[entry['id']] = entry
        return result
