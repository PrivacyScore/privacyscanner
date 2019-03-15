import socket
import ssl
from collections import namedtuple
import smtplib
from pathlib import Path

from privacyscanner.scanmodules import ScanModule
from privacyscanner.utils import set_default_options
from privacyscanner.utils.tls import get_cipher_info, get_certificate_info


LINUX_CA_FILE = Path('/etc/ssl/certs/ca-certificates.crt')

MailserverResult = namedtuple('MailserverResult',
                              ['banner', 'cipher', 'certificate', 'features',
                               'error'])

class MailScanModule(ScanModule):
    name = 'mail'
    required_keys = ['mail', 'dns']
    dependencies = ['dns']

    def __init__(self, options):
        ca_file = None
        if LINUX_CA_FILE.exists():
            ca_file = str(LINUX_CA_FILE)
        set_default_options(options, {
            'local_hostname': None,
            'timeout': 10,
            'ca_file': ca_file,
            'ca_path': None
        })
        super().__init__(options)

    def scan_site(self, result, meta):
        # We did not find a MX record or an A record for the domain
        if 'mail' not in result:
            return

        mail = result['mail']
        try:
            # MX records are ordered by priority (most preferred first)
            mail_host = result['dns'][mail['domain']]['MX'][0]['host']
        except (KeyError, IndexError):
            # We have either an error when receiving MX records
            # or have no MX records.
            mail_host = mail['domain']

        has_cas = (self.options['ca_file'] is not None or
                   self.options['ca_path'] is not None)
        if not has_cas:
            self.logger.warning('No CA certificates loaded. Cannot check for trust.')

        conn = smtplib.SMTP(local_hostname=self.options['local_hostname'],
                            timeout=self.options['timeout'])
        mail['reachable'] = False
        try:
            # The Python API of smtplib has a flaw: If you pass the host
            # to the initializer, it will connect and set self._host to
            # the host, but will not return the first message after connecting.
            # We want that message, because it might contain a version number.
            # You get the first message if you do not pass the host to the
            # initializer, but call connect with the host yourself. However,
            # this does not set self._host and therefore .starttls() fails.
            # So we add this ugly hack, which sets self._host before connect.
            conn._host = mail_host
            code, banner = conn.connect(mail_host)
            mail['banner'] = banner.decode('utf-8', errors='replace')
            mail['reachable'] = True
            mail['has_starttls'] = None
            conn.ehlo_or_helo_if_needed()
            has_starttls = conn.has_extn('STARTTLS')
            mail['has_starttls'] = has_starttls
            if has_starttls:
                context = ssl.create_default_context(
                    cafile=self.options['ca_file'],
                    capath=self.options['ca_path']
                )
                context.check_hostname = has_cas
                context.verify_mode = ssl.CERT_REQUIRED if has_cas else ssl.CERT_NONE
                context.set_ciphers('ALL@SECLEVEL=0')
                try:
                    conn.starttls(context=context)
                    is_trusted = True if has_cas else None
                except ssl.CertificateError:
                    is_trusted = False
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    conn.connect(mail_host)
                    conn.starttls(context=context)
                conn.ehlo_or_helo_if_needed()

                mail.update(get_cipher_info(conn.sock.cipher()))
                cert_der = conn.sock.getpeercert(binary_form=True)
                mail['certificate'] = get_certificate_info(cert_der)
                mail['certificate']['is_trusted'] = is_trusted
            code, msg = conn.verify('root')
            mail['allows_vrfy'] = code in (250, 251, 252, 550, 551, 553)
            code, msg = conn.expn('admin')
            mail['allows_expn'] = code in (250, 550)
        except smtplib.SMTPHeloError:
            mail['error'] = 'EHLO'
        except smtplib.SMTPException:
            mail['error'] = 'smtp_other'
        except ConnectionRefusedError:
            mail['error'] = 'connection_refused'
        except socket.timeout:
            mail['error'] = 'socket_timeout'
        except socket.gaierror:
            mail['error'] = 'socket_addressinfo'
        finally:
            # We only close the connection if we are actually connected
            # (yes, this how smtplib checks for this)
            if hasattr(conn, 'sock') and conn.sock:
                conn.close()

        result.mark_dirty('mail')
