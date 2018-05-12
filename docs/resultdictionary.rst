The result dictionary
=====================

Privacyscanner provides most of its results in a larger JSON object.

The current dictionary format
-----------------------------

The current result dictionary is somewhat unstructured and contains pieces of
information that are not necessary. It will be replaced in the future. See the
following table for the result dictionary's keys:

+---------------------------------------+------------------+-------------+---------+
| Key                                   | Type             | Scan module | Remarks |
+=======================================+==================+=============+=========+
| reachable                             | boolean          | network     |         |
+---------------------------------------+------------------+-------------+---------+
| final_url                             | string           | network     |         |
+---------------------------------------+------------------+-------------+---------+
| https                                 | boolean          | network     |         |
+---------------------------------------+------------------+-------------+---------+
| final_url_is_https                    | boolean          | network     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_a_records                          | list[mxarecord]  | network     |         |
+---------------------------------------+------------------+-------------+---------+
| a_records                             | list[ip]         | network     |         |
+---------------------------------------+------------------+-------------+---------+
| a_locations                           | list[string]     | network     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_records                            | list[mxrecord]   | network     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_locations                          | list[string      | network     |         |
+---------------------------------------+------------------+-------------+---------+
| a_records_reverse                     | list[reversea]   | network     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_a_records_reverse                  | list[mxreversea] | network     |         |
+---------------------------------------+------------------+-------------+---------+
| final_https_url                       | string           | network     |         |
+---------------------------------------+------------------+-------------+---------+
| tracker_requests_elapsed_seconds      | float            | openwpm     |         |
+---------------------------------------+------------------+-------------+---------+
| third_party_requests                  | list[request]    | openwpm     |         |
+---------------------------------------+------------------+-------------+---------+
| redirected_to_https                   | boolean          | openwpm     |         |
+---------------------------------------+------------------+-------------+---------+
| initial_url                           | string           | openwpm     |         |
+---------------------------------------+------------------+-------------+---------+
| third_parties_count                   | integer          | openwpm     |         |
+---------------------------------------+------------------+-------------+---------+
| flashcookies                          | list[string]     | openwpm     |         |
+---------------------------------------+------------------+-------------+---------+
| responses                             | list[response]   | openwpm     |         |
+---------------------------------------+------------------+-------------+---------+
| third_parties                         | list[string]     | openwpm     |         |
+---------------------------------------+------------------+-------------+---------+
| google_analytics_present              | boolean          | openwpm     |         |
+---------------------------------------+------------------+-------------+---------+
| google_analytics_anonymizeIP_set      | boolean          | openwpm     |         |
+---------------------------------------+------------------+-------------+---------+
| google_analytics_anonymize_IP_not_set | integer          | openwpm     |         |
+---------------------------------------+------------------+-------------+---------+
| cookie_stats                          | cookiestats      | openwpm     |         |
+---------------------------------------+------------------+-------------+---------+
| openwpm_final_url                     | string           | openwpm     |         |
+---------------------------------------+------------------+-------------+---------+
| mixed_content                         | boolean          | openwpm     |         |
+---------------------------------------+------------------+-------------+---------+
| headerchecks                          | headerchecks     | openwpm     |         |
+---------------------------------------+------------------+-------------+---------+
| third_party_requests_count            | integer          | openwpm     |         |
+---------------------------------------+------------------+-------------+---------+
| requests                              | list[request]    | openwpm     |         |
+---------------------------------------+------------------+-------------+---------+
| cookies_count                         | integer          | openwpm     |         |
+---------------------------------------+------------------+-------------+---------+
| requests_count                        | integer          | openwpm     |         |
+---------------------------------------+------------------+-------------+---------+
| tracker_requests                      | list[request]    | openwpm     |         |
+---------------------------------------+------------------+-------------+---------+
| success                               | boolean          | openwpm     |         |
+---------------------------------------+------------------+-------------+---------+
| profilecookies                        | list[cookie]     | openwpm     |         |
+---------------------------------------+------------------+-------------+---------+
| flashcookies_count                    | integer          | openwpm     |         |
+---------------------------------------+------------------+-------------+---------+
| leaks                                 | list[string]     | serverleaks |         |
+---------------------------------------+------------------+-------------+---------+
| web_either_crl_or_ocsp_severity       | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_default_cipher_severity           | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_default_cipher_finding            | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_session_ticket                    | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_caa_record_severity               | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_strong_keysize_severity           | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_has_hsts_preload                  | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_has_protocol_tls1_1_finding       | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_has_hsts_header                   | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_strong_sig_algorithm              | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_has_protocol_sslv2                | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_has_protocol_tls1_2               | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_certificate_transparency_severity | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_has_protocol_tls1_2_severity      | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_has_protocol_sslv2_severity       | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_has_protocol_tls1_finding         | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_offers_ocsp                       | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_default_protocol                  | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_ocsp_must_staple                  | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_has_hsts_header_sufficient_time   | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_session_ticket_severity           | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_testssl_missing_ids               | list[string]     | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_default_cipher                    | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_strong_keysize                    | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_vulnerabilities                   | vulnerabilities  | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_ciphers                           | ciphers          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_has_protocol_tls1_2_finding       | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_default_protocol_severity         | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_san_finding                       | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_cert_trusted_reason               | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_cipher_order_severity             | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_certificate_not_expired           | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_either_crl_or_ocsp                | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_ocsp_stapling                     | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_ocsp_must_staple_severity         | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_pfs                               | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_caa_record                        | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_cipher_order                      | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_session_ticket_finding            | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_pfs_severity                      | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_valid_san_severity                | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_has_protocol_tls1_1               | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_has_protocol_sslv3                | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_has_ssl                           | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_has_protocol_sslv3_finding        | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_certificate_transparency          | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_has_protocol_tls1_3               | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_has_protocol_tls1_1_severity      | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_keysize                           | integer          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_valid_san                         | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_has_hpkp_header                   | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_has_protocol_tls1_3_finding       | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_has_protocol_tls1_3_severity      | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_has_protocol_sslv2_finding        | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_default_protocol_finding          | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_has_protocol_sslv3_severity       | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_strong_sig_algorithm_severity     | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_ocsp_stapling_severity            | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_sig_algorithm                     | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_has_protocol_tls1                 | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_certificate_not_expired_finding   | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_has_hsts_preload_header           | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_has_protocol_tls1_severity        | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| web_cert_trusted                      | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_has_ssl                            | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_has_protocol_sslv3_severity        | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_strong_keysize                     | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_san_finding                        | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_either_crl_or_ocsp                 | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_string_sig_algorithm               | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_certificate_not_expired_finding    | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_has_protocol_sslv3_finding         | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_ssl_finished                       | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_session_ticket_severity            | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_certificate_transparency           | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_has_protocol_tls1_3_finding        | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_default_protocol                   | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_has_protocol_sslv2_severity        | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_ocsp_stapling                      | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_has_protocol_tls1_2                | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_default_cipher_severity            | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_ocsp_must_staple_severity          | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_has_protocol_tls1_finding          | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_has_protocol_sslv2                 | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_valid_san_severity                 | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_caa_record                         | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_has_protocol_tls1_1_finding        | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_cipher_order_severity              | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_strong_sig_algorithm_severity      | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_has_protocol_tls1_1_severity       | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_session_ticket_finding             | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_has_protocol_tls1_2_finding        | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_strong_keysize_severity            | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_cert_trusted_reason                | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_certificate_transparency_severity  | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_has_protocol_sslv3                 | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_default_cipher_finding             | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_cert_trusted                       | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_either_crl_or_ocsp_severity        | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_cipher_order                       | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_default_cipher                     | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_session_ticket                     | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_certificate_not_expired            | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_valid_san                          | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_ciphers                            | ciphers          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_default_protocol_severity          | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_keysize                            | integer          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_has_protocol_tls1_severity         | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_caa_record_severity                | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_ocsp_stapling_severity             | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_default_protocol_finding           | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_testssl_missing_ids                | list[string]     | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_offers_ocsp                        | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_has_protocol_sslv2_finding         | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_has_protocol_tls1_3                | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_vulnerabilities                    | vulnerabilities  | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_pfs_severity                       | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_sig_algorihm                       | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_has_protocol_tls1_3_severity       | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_has_protocol_tls1                  | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_has_protocol_tls1_1                | boolean          | testssl     |         |
+---------------------------------------+------------------+-------------+---------+
| mx_has_protocol_tls1_2_severity       | string           | testssl     |         |
+---------------------------------------+------------------+-------------+---------+


The response object
^^^^^^^^^^^^^^^^^^^

+----------------------+--------------+-------------------------------------+
| Key                  | Type         | Remarks                             |
+======================+==============+=====================================+
| method               | string       | GET, POST etc.                      |
+----------------------+--------------+-------------------------------------+
| url                  | string       |                                     |
+----------------------+--------------+-------------------------------------+
| time_stamp           | string       | Example: "2018-05-04T16:09:07.897Z" |
+----------------------+--------------+-------------------------------------+
| response_status_text | string       |                                     |
+----------------------+--------------+-------------------------------------+
| referrer             | string       |                                     |
+----------------------+--------------+-------------------------------------+
| headers              | list[header] |                                     |
+----------------------+--------------+-------------------------------------+
| response_status      | integer      |                                     |
+----------------------+--------------+-------------------------------------+


The header object
^^^^^^^^^^^^^^^^^

The header object is a list containing the header name as first element and the
header value as second element.


The cookiestats object
^^^^^^^^^^^^^^^^^^^^^^

The cookiestats objects contains various pieces of information of cookies.

+---------------------------+--------------+----------------------------------------------------+
| Key                       | Type         | Explanation                                        |
+===========================+==============+====================================================+
| third_party_flash         | integer      | Third-party flash cookies                          |
+---------------------------+--------------+----------------------------------------------------+
| first_party_long          | integer      | First-party cookies with a long runtime (??? days) |
+---------------------------+--------------+----------------------------------------------------+
| third_party_short         | integer      | Third-party cookies with a short runtime (???)     |
+---------------------------+--------------+----------------------------------------------------+
| third_party_track_domains | list[string] | ???                                                |
+---------------------------+--------------+----------------------------------------------------+
| first_party_abort         | integer      | ???                                                |
+---------------------------+--------------+----------------------------------------------------+
| third_party_track         | integer      | ???                                                |
+---------------------------+--------------+----------------------------------------------------+
| first_party_flash         | integer      | ???                                                |
+---------------------------+--------------+----------------------------------------------------+
| third_party_track_uniq    | integer      | ???                                                |
+---------------------------+--------------+----------------------------------------------------+
| third_party_long          | integer      | Third-party cookies with long runtime (???)        |
+---------------------------+--------------+----------------------------------------------------+


The headerchecks object
^^^^^^^^^^^^^^^^^^^^^^^

The headerchecks object holds pieces of information about security related headers.
The object's key contains the header name, while the value contains the information
object. The information object has the keys "status" and "value" (both strings). See
the following example::

   {
       "content-security-policy": {
           "status": "MISSING",
           "value": ""
       }
   }

The following headers (i.e. keys of the headercheck object) are supported:

* x-powered-by
* referrer-policy
* content-security-policy
* server
* x-content-type-options
* x-frame-options
* x-xss-protection


The request object
^^^^^^^^^^^^^^^^^^

+----------+--------+-----------------------------------------------+
| Key      | Type   | Remark                                        |
+==========+========+===============================================+
| method   | string | HTTP method (GET/POST/...)                    |
+----------+--------+-----------------------------------------------+
| headers  | string | JSON encoded headers as string (yes, really!) |
+----------+--------+-----------------------------------------------+
| url      | string |                                               |
+----------+--------+-----------------------------------------------+
| referrer | string |                                               |
+----------+--------+-----------------------------------------------+


The ciphers object
^^^^^^^^^^^^^^^^^^

The cipher object contains various cipher groups as keys and an information
object as value. The information object contains a key "finding" and a key
"severity". The following cipher groups are available:

* std_3DES
* std_HIGH
* std_128Bit
* std_EXPORT
* std_NULL
* std_DES+64Bit
* std_aNULL
* std_STRONG


The vulnerabilities object
^^^^^^^^^^^^^^^^^^^^^^^^^^

The vulnerabilities object contains various TLS-based vulnerabilities as keys
and an information object as value. The information object contains the following
keys: finding, cve, severity (all strings). The following vulnerabilities are
supported:

* LOGJAM_common_primes
* sec_client_renego
* beast
* secure_renego
* drown
* breach
* lucky13
* sweet32
* ccs
* ticketbleed
* rc4
* heartbleed
* crime
* freak
* poodle_ssl
* logjam

The mxarecord list
^^^^^^^^^^^^^^^^^^

The mxarecord list contains two elements. The first element is the priority of
the MX record. The second element is a list of IP addresses. To fill that list,
all MX records will be taken and resolved for A records.

Example::

   [10, ["127.0.0.1", "127.0.1.1"]]


The cookie object
^^^^^^^^^^^^^^^^^

+--------------+---------+-----------------------+
| Key          | Type    | Remark                |
+==============+=========+=======================+
| accessed     | integer | ???                   |
+--------------+---------+-----------------------+
| creationTime | integer |                       |
+--------------+---------+-----------------------+
| name         | string  |                       |
+--------------+---------+-----------------------+
| value        | string  |                       |
+--------------+---------+-----------------------+
| expiry       | integer |                       |
+--------------+---------+-----------------------+
| baseDomain   | string  |                       |
+--------------+---------+-----------------------+
| path         | string  |                       |
+--------------+---------+-----------------------+
| host         | string  |                       |
+--------------+---------+-----------------------+
| isHttpOnly   | integer | Yes, it is no boolean |
+--------------+---------+-----------------------+
| isSecure     | integer | Yes, it it no boolean |
+--------------+---------+-----------------------+


The future result dictionary
----------------------------

It is not decided yet how this will look like. However, there are already
some ideas what to change:

* All web_* and mx_* entries from testssl should move to own on dictionary
  without prefix. Those dictionary will be named tls_web and tls_mail.
* Remove the findings keys for testssl checks. If there are static strings,
  remove them without substitution. Otherwise provide a new key with the
  information provided in the finding (with the value only, not containing
  formatting or english sentences)
* Remove the severity keys for testssl checks. Either convert them into
  booleans or concrete numbers to evaluate oneself (e.g. key size)
* Google Analytics detection will be an own dictionary
