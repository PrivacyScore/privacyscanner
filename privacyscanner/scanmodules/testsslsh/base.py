import io
import re
import tarfile
from pathlib import Path

from privacyscanner.exceptions import RescheduleLater
from privacyscanner.scanmodules import ScanModule
from privacyscanner.scanmodules.testsslsh.scanner import TestsslshScanner, Parameter, TestsslshFailed, \
    TestsslshFailedPartially
from privacyscanner.utils import set_default_options, download_file
from privacyscanner.utils.tls import get_cipher_info


DOWNLOAD_URL = 'https://github.com/drwetter/testssl.sh/archive/3.0.tar.gz'
DOWNLOAD_HASH = 'a1d95c0ffc9a223bf3dacb831433d3cbf31cae03f3d376de2850e52bec0a688a'

_TESTSSL_PROTOCOL_NEGOTIATED_REGEXP = re.compile('^Default protocol (TLS1.[0-3]|SSLv[23])$')
_TESTSSL_SUITE_NAME = re.compile('^([A-Za-z0-9-]+)(,| |$)')
_TESTSSL_DH = re.compile('(\d+) bit (DH|ECDH)')
_TESTSSL_ECDH_CURVE = re.compile(r'\(([^)]+)\)')


class IncompleteStage(Exception):
    def __init__(self, partial_result):
        self.partial_result = partial_result
        super().__init__()


class TestsslshScanModuleBase(ScanModule):
    name = None  # type: str
    required_keys = None  # type: list
    target_type = None  # type: str
    target_parameters = None  # type: list
    dependencies = ['chromedevtools', 'dns']

    def __init__(self, options):
        set_default_options(options, {
            'install_base_dir': options['storage_path'] / 'testsslsh',
            'download_url': DOWNLOAD_URL,
            'download_hash': DOWNLOAD_HASH,
            'stages': ['basic', 'vulns', 'vulns_ids'],
        })

        for stage in options['stages']:
            if not hasattr(self, '_scan_stage_' + stage):
                raise ValueError('Invalid stage: `{}`.'.format(stage))

        super().__init__(options)
        self._install_dir = self.options['install_base_dir'] / self.options['download_hash']

    def scan_site(self, result, meta):
        if not self._can_run(result):
            self.logger.info('Skipping testssl.sh checks: No (START)TLS found.')
            return
        stages = self.options['stages']
        testssl_key = 'testssl_' + self.target_type
        if testssl_key not in result:
            result[testssl_key] = {
                'current_stage': stages[0],
                'stages': {}
            }
        result.mark_dirty(testssl_key)
        testssl = result[testssl_key]
        stage_key = testssl['current_stage']

        self.logger.info('Current stage: %s', stage_key)
        if stage_key not in stages:
            self.logger.error('Stage `%s` is not available', stage_key)
            return

        if stage_key not in testssl['stages']:
            testssl['stages'][stage_key] = {'status': 'open'}
        stage_dict = testssl['stages'][stage_key]

        scan_result = None
        try:
            stage_method = getattr(self, '_scan_stage_' + stage_key)
            host = self._get_host(result)
            scan_result = stage_method(host, self.target_parameters)
        except IncompleteStage as e:
            self.logger.info('testssl.sh result is incomplete.')
            scan_result = e.partial_result
            stage_dict['status'] = 'incomplete'
        except TestsslshFailed as e:
            self.logger.error('testssl.sh failed with exit code %s: %s',
                              e.exit_code, e)
            stage_dict['status'] = 'failed'
            stage_dict['error_code'] = e.exit_code
            stage_dict['error_message'] = str(e)
        except Exception as e:
            stage_dict['status'] = 'failed_with_bug'
            stage_dict['error_code'] = -2000
            stage_dict['error_message'] = '{}: {}'.format(e.__class__.__name__, e)
            self.logger.exception('Programming error in testsslsh')
            raise
        else:
            self.logger.info('testssl.sh result is complete.')
            stage_dict['status'] = 'complete'

        if scan_result:
            target_result = result[self.target_type]
            for key, value in scan_result.items():
                if key in target_result:
                    continue
                target_result[key] = value
            result.mark_dirty(self.target_type)

        has_failed = stage_dict['status'] != 'complete'
        if has_failed:
            del testssl['current_stage']
            return

        try:
            next_stage = stages[stages.index(stage_key) + 1]
        except IndexError:
            del testssl['current_stage']
            self.logger.info('%s was the final stage.', stage_key)
            return
        self.logger.info('Next stage: %s', next_stage)
        testssl['current_stage'] = next_stage
        raise RescheduleLater(10)

    def _scan_stage_basic(self, target, extra_parameters):
        """Stage 0 scan: Contains the most relevant checks.

        These include:
        - Protocols (SSLv3, TLSv1.0 - TLSv1.3)
        - Standard ciphers, including weak ciphers (RC4, ...)
        - Forward Secrecy support

        """
        scanner = TestsslshScanner(self._install_dir)
        scanner.add_parameters(Parameter.PROTOCOLS,
                               Parameter.STANDARD_CIPHERS,
                               Parameter.CHECK_FORWARD_SECRECY,
                               Parameter.SERVER_DEFAULTS,
                               Parameter.SERVER_PREFERENCE,
                               Parameter.PHONE_OUT,
                               *extra_parameters)
        try:
            scan_result = scanner.scan(target)
            incomplete = False
        except TestsslshFailedPartially as e:
            scan_result = e.partial_result
            incomplete = True
        findings = ScanResultFindings(scan_result, self.logger)

        forward_secrecy = {
            'available': None,
            'ciphers': None
        }
        protocols = {
            'SSL 2': None,
            'SSL 3': None,
            'TLS 1.0': None,
            'TLS 1.2': None,
            'TLS 1.3': None,
        }
        ciphers = {
            '128Bit': None,
            '3DES': None,
            'DES_and_64Bit': None,
            'EXPORT': None,
            'HIGH': None,
            'NULL': None,
            'STRONG': None,
            'aNULL': None,
        }
        ocsp = {
            'valid': None,
            'stapling': None,
            'must_staple': None,
        }
        resumption = {
            'session_id': None,
            'session_ticket': None,
        }
        certificate_transparency = {
            'valid': None,
            'has_extension': None
        }
        cipher_order = {}
        tls_result = {
            'forward_secrecy': forward_secrecy,
            'certificate_transparency': certificate_transparency,
            'prefer_server_ciphers': None,
            'cipher_order': cipher_order,
            'ocsp': ocsp,
            'supported_protocols': protocols,
            'supported_cipherlists': ciphers,
            'resumption': resumption,
        }

        pfs = findings.get('PFS', ('offered', 'not offered'))
        if pfs:
            forward_secrecy['available'] = pfs == 'offered'

        pfs_ciphers = findings.get('PFS_ciphers')
        if pfs_ciphers:
            forward_secrecy['ciphers'] = pfs_ciphers.split()

        pfs_curves = findings.get('PFS_ECDHE_curves')
        if pfs_curves:
            forward_secrecy['curves'] = pfs_curves.split()

        protocol_name_map = {
            'SSLv2': 'SSL 2',
            'SSLv3': 'SSL 3',
            'TLS1': 'TLS 1.0',
            'TLS1_1': 'TLS 1.1',
            'TLS1_2': 'TLS 1.2',
            'TLS1_3': 'TLS 1.3'
        }
        for source_key, target_key in protocol_name_map.items():
            protocol = findings.get(source_key, (
                'offered',
                'offered with final',
                'offered (deprecated)',
                'not offered',
                'is not offered', # Why, testssl.sh, WHY?
                'not offered and downgraded to a weaker protocol',
                'not offered + downgraded to weaker protocol', # ...
            ))
            if protocol is None:
                continue
            protocols[target_key] = protocol in ('offered', 'offered with final',
                                                 'offered (deprecated)')

            # Why, testssl.sh, WHY?
            order_key = source_key.replace('TLS', 'TLSv')
            cipherorder_proto = findings.get('cipherorder_' + order_key)
            if cipherorder_proto:
                cipher_order[target_key] = cipherorder_proto.split()

        # We need protocol to be defined when looking at the cipher that has
        # been negotiated. Normally, protocol will be overriden in this
        # block.
        protocol = None
        protocol_negotiated = findings.get('protocol_negotiated')
        if protocol_negotiated:
            if 'Default protocol' in protocol_negotiated:
                match = _TESTSSL_PROTOCOL_NEGOTIATED_REGEXP.match(protocol_negotiated)
                if match:
                    protocol = protocol_name_map[match.group(1).replace('.', '_')]
                    tls_result['protocol'] = protocol

        cipher_negotiated = findings.get('cipher_negotiated')
        if cipher_negotiated:
            cipher = {
                'cipher': None,
                'key_exchange': None,
                'key_exchange_group': None,
                'mac': None
            }
            match_dh = _TESTSSL_DH.search(cipher_negotiated)
            match_curve = _TESTSSL_ECDH_CURVE.search(cipher_negotiated)
            match_suite = _TESTSSL_SUITE_NAME.search(cipher_negotiated)
            curve = None
            if match_suite:
                bits = 0
                if match_dh:
                    bits = int(match_dh.group(1))
                    dh = match_dh.group(2)
                    if match_curve and dh == 'ECDH':
                        curve = match_curve.group(1)
                cipher_tuple = (match_suite.group(1), protocol, bits)
                cipher.update(get_cipher_info(cipher_tuple))
                cipher['key_exchange_group'] = curve
            tls_result.update(cipher)

        cipher_map = {'DES_and_64Bit': 'cipherlist_DES+64Bit'}
        for key in ciphers:
            source_key = cipher_map.get(key, 'cipherlist_' + key)
            cipherlist = findings.get(source_key, ('offered', 'not offered'))
            if cipherlist is None:
                continue
            ciphers[key] = cipherlist == 'offered'

        cipher_order = findings.get('cipher_order',
                                    ('server', 'NOT cipher order configured'))
        if cipher_order:
            tls_result['prefer_server_ciphers'] = cipher_order == 'server'

        ocsp_stapling = findings.get('OCSP_stapling')
        if ocsp_stapling:
            # Note: We have no assertions here, because testssl.sh uses a
            # dynamic string here. Currently, only 'offered' is the true-case.
            ocsp['stapling'] = ocsp_stapling == 'offered'

        ocsp_revoked = findings.get('cert_ocspRevoked')
        if ocsp_revoked:
            # Again, no _assert_findings. Options are either 'revoked',
            # 'not revoked', or the responder's response.
            if ocsp_revoked == 'revoked':
                ocsp['valid'] = False
            elif ocsp_revoked == 'not revoked':
                ocsp['valid'] = True
            else:
                ocsp['response'] = ocsp_revoked

        ocsp_must_staple = findings.get('cert_mustStapleExtension', (
            '--', 'supported', 'extension detected but no OCSP stapling provided'
        ))
        if ocsp_must_staple:
            ocsp['must_staple'] = ocsp_must_staple != '--'

        session_id_resumption = findings.get('sessionresumption_ID', (
            'No Session ID, no resumption',
            'supported',
            'not supported',
            "check couldn't be performed because of client authentication",
            'check failed, pls report'
        ))
        if session_id_resumption:
            if session_id_resumption == 'supported':
                resumption['session_id'] = True
            elif session_id_resumption in ('No Session ID, no resumption', 'not supported'):
                resumption['session_id'] = False

        session_ticket_support = findings.get('sessionresumption_ticket', (
            'supported',
            'not supported',
            "check couldn't be performed because of client authentication",
            'check failed, pls report'
        ))
        if session_ticket_support:
            if session_ticket_support == 'supported':
                resumption['session_ticket'] = True
            elif session_ticket_support == 'not supported':
                resumption['session_ticket'] = False

        finding_ct = findings.get('certificate_transparency')
        if finding_ct:
            if finding_ct == 'yes (certificate extension)':
                certificate_transparency['has_extension'] = True

        if incomplete:
            raise IncompleteStage(tls_result)
        return tls_result

    def _scan_stage_vulns(self, target, extra_parameters):
        """Stage 1 scan: Contains vulnerabilities which are IDS-proof"""
        scanner = TestsslshScanner(self._install_dir)
        scanner.add_parameters(Parameter.VULN_RENEGOTIATION,
                               Parameter.VULN_CRIME,
                               Parameter.VULN_BREACH,
                               Parameter.VULN_POODLE,
                               Parameter.VULN_TLS_FALLBACK,
                               Parameter.VULN_SWEET32,
                               Parameter.VULN_FREAK,
                               Parameter.VULN_DROWN,
                               Parameter.VULN_LOGJAM,
                               Parameter.VULN_BEAST,
                               Parameter.VULN_LUCKY13,
                               Parameter.VULN_RC4,
                               *extra_parameters)
        scan_result = scanner.scan(target)
        findings = ScanResultFindings(scan_result, self.logger)

        vulns = {
            'BEAST': None,
            'BREACH': None,
            'CRIME': None,
            'DROWN': None,
            'FREAK': None,
            'Logjam': None, # ?
            'POODLE': None,
            'Sweet32': None,
            'TLS_FALLBACK_SCSV': None,
            'Lucky13': None,
            'RC4': None,
            'Renegotiation': None,
            'Renegotiation_client': None,
        }

        beast = findings.get('BEAST')
        if beast:
            if 'VULNERABLE' in beast:
                vulns['BEAST'] = {'vulnerable': True, 'ciphers': None}
                beast_ciphers = findings.get('BEAST_CBC_TLS1')
                if beast_ciphers:
                    vulns['BEAST']['ciphers'] = beast_ciphers.split()
            else:
                vulns['BEAST'] = {'vulnerable': False}

        vuln_no_extra = {
            'BREACH': 'BREACH',
            'CRIME': 'CRIME_TLS',
            'Sweet32': 'SWEET32',
            'DROWN': 'DROWN',
            'FREAK': 'FREAK',
            'POODLE': 'POODLE_SSL',  # TODO: handle POODLE_TLS once implemented
            'RC4': 'RC4',
            'Renegotiation': 'secure_renego',
            'Renegotiation_client': 'secure_client_renego'
        }
        for vuln_name, vuln_key in vuln_no_extra.items():
            finding = findings.get(vuln_key)
            if finding:
                vulns[vuln_name] = {'vulnerable': 'VULNERABLE' in finding}

        sweet32 = findings.get('SWEET32', ('uses 64 bit block ciphers',
                                           'not vulnerable'))
        if sweet32:
            vulns['Sweet32'] = {'vulnerable': sweet32 == 'uses 64 bit block ciphers'}

        logjam = findings.get('LOGJAM')
        if logjam:
            login_common_primes = findings.get('LOGJAM-common_primes')
            # TODO: Implement me

        fallback = findings.get('fallback_SCSV')
        if fallback:
            # Do we really want to classify this as an vulnerability like
            # testssl.sh does?
            vulns['TLS_FALLBACK_SCSV'] = {'vulnerable': fallback != 'supported' and
                                          'no protocol below ' not in fallback}

        lucky13 = findings.get('LUCKY13')
        if lucky13:
            # experimental; can be a false positive with a fixed openssl version
            vulns['Lucky13'] = {'vulnerable': 'potentially vulnerable' in lucky13}

        return vulns

    def _scan_stage_vulns_ids(self, target, extra_parameters):
        """Stage 2 scan: Contains vulnerabilities that could trigger an IDS"""
        scanner = TestsslshScanner(self._install_dir)
        scanner.add_parameters(Parameter.VULN_HEARTBLEED,
                               Parameter.VULN_CCS_INJECTION,
                               Parameter.VULN_TICKETBLEED,
                               Parameter.VULN_ROBOT,
                               *extra_parameters)
        scan_result = scanner.scan(target)
        findings = ScanResultFindings(scan_result, self.logger)

        vulns = {
            'Heartbleed': None,
            'CCS_Injection': None,
            'Ticketbleed': None,
            'ROBOT': None
        }
        vuln_no_extra = {
            'Heartbleed': 'heartbleed',
            'Ticketbleed': 'ticketbleed',
            'ROBOT': 'ROBOT'
        }
        for vuln_name, vuln_key in vuln_no_extra.items():
            finding = findings.get(vuln_key)
            if finding:
                vulns[vuln_name] = {'vulnerable': 'VULNERABLE' in finding}

        ccs = findings.get('CCS')
        if ccs:
            vulns['CCS_Injection'] = {'vulnerable': 'VULNERABLE' in ccs}
            if 'likely VULNERABLE with' in ccs:
                alert_byte = ccs.replace('likely VULNERABLE with ', '')
                vulns['CCS_Injection']['alert_type'] = 'unknown_alert_0x{}'.format(alert_byte)
            elif 'likely VULNERABLE' in ccs:
                vulns['CCS_Injection']['alert_type'] = 'bad_record_mac'

            if 'probably not vulnerable but' in ccs:
                byte_start = ccs.find('0x')
                byte_end = ccs.find(' ', byte_start)
                if byte_start > 0 and byte_end > 0:
                    alert_byte = ccs[byte_start:byte_end]
                    if alert_byte == '0x0A':
                        alert_type = 'unexpected_message'
                    elif alert_byte == '0x28':
                        alert_type = 'handshake_failure'
                    else:
                        alert_type = 'unknown_alert_{}'.format(alert_byte)
                    vulns['CCS_Injection']['alert_type'] = alert_type

        return vulns

    def update_dependencies(self):
        install_base_dir = self.options['install_base_dir']
        install_base_dir.mkdir(parents=True, exist_ok=True)
        hash_symlink = (install_base_dir / self.options['download_hash'])
        if hash_symlink.exists():
            self.logger.info('Expected testssl.sh version is already installed.')
            return
        self.logger.info('Downloading testssl.sh from %s', self.options['download_url'])
        with io.BytesIO() as f:
            download_file(self.options['download_url'], f,
                          verify_hash=self.options['download_hash'])
            f.seek(0)
            with tarfile.open(fileobj=f) as tarball:
                directory_name = Path(tarball.next().name).parts[0]
                tarball.extractall(path=str(install_base_dir))
        hash_symlink.symlink_to(directory_name, target_is_directory=True)
        self.logger.info('Successfully installed testssl.sh')

    def _get_host(self, result):
        raise NotImplemented

    def _can_run(self, result):
        raise NotImplemented


class ScanResultFindings:
    def __init__(self, scan_result, logger):
        self._scan_result = scan_result
        self._logger = logger

    def get(self, key, assertions=None):
        if key not in self._scan_result:
            return None
        finding = self._scan_result[key]['finding']
        if assertions is not None:
            if isinstance(assertions, (list, tuple)):
                if finding not in assertions:
                    msg = 'Finding for %s is not expected: %s' % (key, finding)
                    self._logger.error(msg)
                    raise ValueError(msg)
        return finding
