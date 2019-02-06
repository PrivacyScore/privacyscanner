from collections import namedtuple
import smtplib

from privacyscanner.scanmodules import ScanModule
from privacyscanner.utils import set_default_options
from privacyscanner.utils.tls import get_cipher_info, get_certificate_info


MailserverResult = namedtuple('MailserverResult',
                              ['banner', 'cipher', 'certificate', 'features',
                               'error'])

class MailScanModule(ScanModule):
    name = 'mail'
    required_keys = ['mail', 'dns']
    dependencies = ['dns']

    def __init__(self, options):
        set_default_options(options, {
            'local_hostname': None,
            'timeout': 10
        })
        super().__init__(options)

    def scan_site(self, result, meta):
        mail = result['mail']
        try:
            # MX records are ordered by priority (most preferred first)
            mail_host = result['dns'][mail['domain']]['MX'][0]['host']
        except (KeyError, IndexError):
            # We have either an error when receiving MX records
            # or have no MX records.
            mail_host = mail['domain']

        conn = smtplib.SMTP(local_hostname=self.options['local_hostname'],
                            timeout=self.options['timeout'])
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
            conn.ehlo_or_helo_if_needed()
            has_starttls = conn.has_extn('STARTTLS')
            mail['has_starttls'] = has_starttls
            if has_starttls:
                conn.starttls()
                mail.update(get_cipher_info(conn.sock.cipher()))
                cert_der = conn.sock.getpeercert(binary_form=True)
                mail['certificate'] = get_certificate_info(cert_der)
            mail['feature'] = conn.esmtp_features
        except smtplib.SMTPHeloError:
            mail['error'] = 'EHLO'
        except smtplib.SMTPException:
            mail['error'] = 'other'
        finally:
            conn.close()

        result.mark_dirty('mail')
