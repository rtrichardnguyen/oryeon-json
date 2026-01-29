from __future__ import annotations

import sys, json, re, ssl, socket, whoisit, subprocess, base64
import tldextract
import dns.resolver
import dns.flags
import dns.name
import geoip2.database
from urllib.parse import urlparse
from ipwhois import IPWhois
from datetime import datetime, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.backends import default_backend


from typing import Dict, Optional, Tuple

import dns.name
import dns.message
import dns.query
import dns.rdatatype
import dns.rdataclass
import dns.resolver
import dns.dnssec
import dns.exception

DNS_RECORDS = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']

SOA_RE = re.compile(
    r'^\s*'
    r'(?P<primary_ns>\S+)\s+'
    r'(?P<resp_mailbox>\S+)\s+'
    r'(?P<serial>\d+)\s+'
    r'(?P<refresh>\d+)\s+'
    r'(?P<retry>\d+)\s+'
    r'(?P<expire>\d+)\s+'
    r'(?P<min_ttl>\d+)'
    r'\s*$'
)

ROOT = Path(__file__).resolve().parents[0]
ZGRAB2 = ROOT / 'tools' / 'zgrab2' / 'zgrab2'

RR_TYPES = ["A", "AAAA", "SOA", "CNAME", "MX", "NS", "TXT", "NAPTR"]

# enums (match your schema)
SRC_AUTH = 0
SRC_RECURSIVE = 1
SRC_NOT_FOUND = 2

DNSSEC_NO_RRSIG = 0
DNSSEC_OK = 1          # "RRSIG present" (presence-based)
DNSSEC_BAD = 2           # we won't reliably detect this without full validation
DNSSEC_NO_DNSKEY = 3

RR_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "NAPTR"]


def _find_zone_via_soa(res: dns.resolver.Resolver, qname: str) -> Optional[str]:
    """
    Walk up labels until we find an SOA; that's the zone apex for our purposes.
    """
    name = dns.name.from_text(qname)
    while True:
        try:
            _ = res.resolve(name, "SOA")  # SOA lookup doesn't require DNSSEC
            return str(name).rstrip(".")
        except dns.resolver.NXDOMAIN:
            return None
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NoNameservers:
            pass

        if name == dns.name.root:
            return None
        name = name.parent()


def _resolve_with_dnssec(
    res: dns.resolver.Resolver, qname: str, rdtype: str
) -> Tuple[Optional[dns.rrset.RRset], Optional[dns.rrset.RRset], Optional[dns.message.Message]]:
    """
    Returns (rrset, rrsig_rrset, full_response) using want_dnssec=True.
    """
    try:
        ans = res.resolve(qname, rdtype, raise_on_no_answer=False)
        resp = ans.response  # dns.message.Message

        rrset = None if ans.rrset is None else ans.rrset

        rrsig = None
        if rrset is not None:
            # RRSIGs sit in the ANSWER section; find the one that covers rdtype
            try:
                rrsig = resp.find_rrset(
                    resp.answer,
                    dns.name.from_text(qname),
                    dns.rdataclass.IN,
                    dns.rdatatype.RRSIG,
                    covers=dns.rdatatype.from_text(rdtype),
                )
            except KeyError:
                rrsig = None

        return rrset, rrsig, resp
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return None, None, None


def _fetch_dnskey(
    res: dns.resolver.Resolver, zone: str
) -> Tuple[Optional[dns.rrset.RRset], Optional[dns.rrset.RRset]]:
    """
    Returns (dnskey_rrset, dnskey_rrsig_rrset) for the zone apex.
    """
    rrset, rrsig, _ = _resolve_with_dnssec(res, zone, "DNSKEY")
    return rrset, rrsig


def _make_key_dict(zone: str, dnskey_rrset: dns.rrset.RRset) -> Dict[dns.name.Name, dns.rrset.RRset]:
    """
    dnspython wants {name: dnskey_rrset} mapping.
    """
    return {dns.name.from_text(zone): dnskey_rrset}


def _validate_rrset(zone: str, rrset: dns.rrset.RRset, rrsig: dns.rrset.RRset, dnskey_rrset: dns.rrset.RRset) -> bool:
    keys = _make_key_dict(zone, dnskey_rrset)
    # raises dns.dnssec.ValidationFailure if bad
    dns.dnssec.validate(rrset, rrsig, keys)
    return True


def build_dnssec_section(domain: str, nameserver: Optional[str] = None) -> Dict:
    """
    Produces:
      {
        "dnssec": { "A": int, ... },
        "remarks": { "has_dnskey": bool, "zone_dnskey_selfsign_ok": bool, "zone": str|None }
      }
    """
    res = dns.resolver.Resolver(configure=True)
    res.use_edns(edns=True, ednsflags=dns.flags.DO)
    res.lifetime = 5.0
    res.timeout = 2.0
    if nameserver:
        res.nameservers = [nameserver]

    zone = _find_zone_via_soa(res, domain)

    out_dnssec: Dict[str, int] = {t: DNSSEC_NO_DNSKEY for t in RR_TYPES}
    remarks = {"has_dnskey": False, "zone_dnskey_selfsign_ok": False, "zone": zone if zone else domain}

    if not zone:
        # can't determine zone -> treat as no DNSKEY
        return {"dnssec": out_dnssec, "remarks": remarks}

    dnskey_rrset, dnskey_rrsig = _fetch_dnskey(res, zone)
    if dnskey_rrset is None:
        # No DNSKEY => enum 3 everywhere (matches your sample when has_dnskey=false)【:contentReference[oaicite:2]{index=2}】
        return {"dnssec": out_dnssec, "remarks": remarks}

    remarks["has_dnskey"] = True

    # "selfsign" check: validate DNSKEY RRset with its own RRSIG using the DNSKEYs themselves.
    if dnskey_rrsig is not None:
        try:
            _validate_rrset(zone, dnskey_rrset, dnskey_rrsig, dnskey_rrset)
            remarks["zone_dnskey_selfsign_ok"] = True
        except dns.dnssec.ValidationFailure:
            remarks["zone_dnskey_selfsign_ok"] = False

    # For each RRtype: check RRSIG exists and validate
    for t in RR_TYPES:
        rrset, rrsig, _ = _resolve_with_dnssec(res, domain, t)
        if rrset is None:
            # You can pick any convention for "not found".
            # Your schema doesn't define a DNSSEC enum for "record absent";
            # most pipelines still set DNSSEC to 0/3 depending on DNSKEY presence.
            out_dnssec[t] = DNSSEC_OK if remarks["has_dnskey"] else DNSSEC_NO_DNSKEY
            continue

        if rrsig is None:
            out_dnssec[t] = DNSSEC_NO_RRSIG
            continue

        try:
            _validate_rrset(zone, rrset, rrsig, dnskey_rrset)
            out_dnssec[t] = DNSSEC_OK
        except dns.dnssec.ValidationFailure:
            out_dnssec[t] = DNSSEC_BAD

    return {"dnssec": out_dnssec, "remarks": remarks}


def _resolve_ips(domain: str) -> list[dict]:
    
    related_ips = []

    answer_A = dns.resolver.resolve(domain, "A")
    answer_AAAA = dns.resolver.resolve(domain, "AAAA")

    for rdata_A in answer_A:
        ttl = str(answer_A.ttl)
        value = str(rdata_A.address)

        related_ips.append({'ttl': ttl, 'value': value})

    for rdata_AAAA in answer_AAAA:
        ttl = str(answer_AAAA.ttl)
        value = str(rdata_AAAA.address)

        related_ips.append({'ttl': ttl, 'value': value})

    return related_ips


def get_zone_soa(domain: str):
    name = dns.name.from_text(domain)

    while True:
        try:
            # try current name
            answer = dns.resolver.resolve(name.to_text(), "SOA")
            return answer[0]      # SOA rdata
        except (dns.resolver.NoAnswer,
                dns.resolver.NXDOMAIN,
                dns.resolver.LifetimeTimeout):
            # move one level up
            try:
                name = name.parent()
            except dns.name.NoParent:
                # we hit the root and never found an SOA
                return None


def get_tls_data(parsed_url: str):

    tls_map = {}

    hostname = parsed_url.hostname
    port = parsed_url.port or 443

    context = ssl.create_default_context()

    with socket.create_connection((hostname, port)) as sock:

        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cipher_suite, tls_protocol, secret_bits = ssock.cipher()
            certificates = ssock.getpeercert()

    tls_map['cipher'] = cipher_suite
    tls_map['count'] = 1 # Only one TLS connection attempt
    tls_map['protocol'] = tls_protocol

def _get_rdap(domain: str) -> dict:

    return whoisit.domain(domain)

def _get_ip_data_rdap(ip: str) -> dict:

    return whoisit.ip(ip)

def _get_ip_data(ip: str, record: str) -> dict:
    
    ip_data_dict = {}
    
    ip_data_dict['ip'] = ip
    ip_data_dict['from_record'] = record
    # TODO: remarks
    ip_data_dict['rdap'] = _get_ip_data_rdap(ip)

    with geoip2.database.Reader('./GeoLite2-ASN.mmdb') as reader:
        response = reader.asn(ip)
        asn = {}
        asn['asn'] = response.autonomous_system_number
        asn['as_org'] = response.autonomous_system_organization
        network = str(response.network)
        asn['network_address'] = network[:network.index('/')]
        asn['prefix_len'] = network[network.index('/') + 1:]
        ip_data_dict['asn'] = asn

    with geoip2.database.Reader('./GeoLite2-City.mmdb') as reader:
        response = reader.city(ip)
        geo = {}
        geo['country'] = response.registered_country.names['en']
        geo['country_code'] = response.registered_country.iso_code
        geo['region'] = response.subdivisions.most_specific.names.get('en')
        geo['region_code'] = response.subdivisions.most_specific.iso_code
        geo['city'] = response.city.name
        geo['postal_code'] = response.postal.code
        geo['latitude'] = response.location.latitude
        geo['longitude'] = response.location.longitude
        geo['timezone'] = response.location.time_zone
        geo['isp'] = None
        geo['org'] = None
        ip_data_dict['geo'] = geo

    return ip_data_dict

def _encode(obj):

    if isinstance(obj, datetime):
        return obj.isoformat() + 'Z'

def _normalize_certificate(ingest_certificate, is_root: bool):

    normalized_cert = {}

    normalized_cert['common_name'] = ingest_certificate['parsed']['issuer']['common_name'][0]
    normalized_cert['organization'] = ingest_certificate['parsed']['issuer']['organization'][0] 
    normalized_cert['country'] = ingest_certificate['parsed']['issuer']['country'][0] 
    normalized_cert['validity_start'] = { '$date' : ingest_certificate['parsed']['validity']['start'] } 
    normalized_cert['validity_end'] = { '$date' : ingest_certificate['parsed']['validity']['end'] } 
    normalized_cert['valid_len'] = ingest_certificate['parsed']['validity']['length'] 

    exts = _get_cert_exts(ingest_certificate['raw'])
    normalized_cert['extensions'] = exts
    normalized_cert['extension_count'] = len(exts) 

    normalized_cert['is_root'] = is_root 

    return normalized_cert

def _get_cert_exts(cert_raw_b64):
    der = base64.b64decode(cert_raw_b64)
    cert = x509.load_der_x509_certificate(der, default_backend())

    exts = []
    for ext in cert.extensions:
        exts.append({
            'critical': ext.critical,
            'name': ext.oid._name or ext.oid.dotted_string,
            'value': str(ext.value),
        })
    return exts

def main():

    if len(sys.argv)!= 2:
        raise ValueError('Incorrect number of arguments was given.')


    result_json = {}

    url = sys.argv[1]
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    ext = tldextract.extract(parsed_url.hostname)
    domain = ext.top_domain_under_public_suffix

    if not domain:
        raise ValueError('Incorrect URL value was given.')

    result_json['url'] = url
    result_json['domain_name'] = domain 
    result_json['dns'] = {}
    result_json['ip_data'] = []
    result_json['rdap'] = {}
    result_json['tls'] = {}


    """ DNS DATA """

    for record in DNS_RECORDS:

        try:
            record_info = {}
            answer = dns.resolver.resolve(domain, record)

            match record:

                case 'A' | 'AAAA':

                    ips = []

                    for rdata in answer:
                        ips.append(rdata.to_text())

                    record_info = ips

                case 'CNAME':

                    cname_rdata = answer[0].to_text()

                    record_info["value"] = cname_rdata
                    record_info["related_ips"] = _resolve_ips(cname_rdata)

                       
                case 'MX':

                    for rdata in answer:
                        pattern = r'^(\d+)\s+([A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+\.?$)'
                        match = re.match(pattern, rdata.to_text())

                        mx_info = {'priority': match.group(1)}

                        mx_info['related_ips'] = _resolve_ips(match.group(2))

                        record_info[match.group(2)] = mx_info

                case 'NS':

                    for i, rdata in enumerate(answer):

                        ip_dict = {}

                        nameserver = rdata.to_text()

                        ip_dict['related_ips'] = _resolve_ips(nameserver)
                        record_info[nameserver] = ip_dict

                case 'TXT':

                    txts = []

                    for rdata in answer:
                        txts.append(rdata.to_text().strip('\\"'))

                    record_info = txts

                case 'SOA':

                    soa_dict = SOA_RE.match(answer[0].to_text())
                    record_info = soa_dict.groupdict()

        
        except dns.resolver.LifetimeTimeout:
            print(f"LifetimeTimeout ERROR '{record}': Timeout while resolving DNS data.")

        except dns.resolver.NXDOMAIN:
            print(f"NXDOMAIN ERROR '{record}': Query name does not exist.")

        except dns.resolver.YXDOMAIN:
            print(f"YXDOMAIN ERROR '{record}': Query name is too long after DNAME substitution.")

        except dns.resolver.NoAnswer:
            print(f"NoAnswer ERROR '{record}': No answer was found for this record.")

        except dns.resolver.NoNameservers:
            print(f"NoNameservers ERROR '{record}': No non-broken nameservers are available to resolve the DNS data.")

        finally:
            result_json['dns'][record] = None if not record_info else record_info
 

    zone_soa_rdata = get_zone_soa(domain)
    if zone_soa_rdata is not None:
        m = SOA_RE.match(zone_soa_rdata.to_text())
        result_json['dns']['zone_SOA'] = m.groupdict() if m else None
    else:
        result_json['dns']['zone_SOA'] = None

    # TODO: dnssec

    sec = build_dnssec_section(domain)
    result_json['dns']['dnssec'] = sec['dnssec']
    result_json['dns']['remarks'] = sec['remarks']

    # TODO: ttls
    # TODO: remarks

    def _resolve_rr(domain: str, rtype: str, auth_ip: str | None):
        """
        Returns:
          (answer_or_None, source_enum, ttl_int, found_bool)
        """
        # 1) Try authoritative
        if auth_ip:
            try:
                r = _resolver_for_nameserver(auth_ip)
                ans = r.resolve(domain, rtype, raise_on_no_answer=False)
                # If no answer section / empty rrset => treat as not found
                if ans.rrset is None:
                    return None, SRC_NOT_FOUND, 0, False
                return ans, SRC_AUTH, int(ans.rrset.ttl), True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                return None, SRC_NOT_FOUND, 0, False
            except dns.exception.DNSException:
                # fall through to recursive
                pass

        # 2) Fallback recursive (system-configured)
        try:
            r = dns.resolver.Resolver()
            r.timeout = 2.0
            r.lifetime = 2.0
            ans = r.resolve(domain, rtype, raise_on_no_answer=False)
            if ans.rrset is None:
                return None, SRC_NOT_FOUND, 0, False
            return ans, SRC_RECURSIVE, int(ans.rrset.ttl), True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return None, SRC_NOT_FOUND, 0, False
        except dns.exception.DNSException:
            return None, SRC_NOT_FOUND, 0, False

    def _resolver_for_nameserver(ip: str) -> dns.resolver.Resolver:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [ip]
        r.timeout = 2.0
        r.lifetime = 2.0
        return r

    def _get_dnskey(zone, auth_ip):
        ans, _, _, found = _resolve_rr(zone, "DNSKEY", auth_ip)
        return bool(found)

    def _pick_authoritative_ns_ip(domain):

        try:
            ns_ans = dns.resolver.resolve(domain, 'NS')
            ns_name = ns_ans[0].to_text().rstrip('.')
            a_ans = dns.resolver.resolve(ns_name, 'A')
            return a_ans[0].address

        except Exception:
            return None

    zone = domain.rstrip('.')
    auth_ip = _pick_authoritative_ns_ip(domain)

    has_dnskey = _get_dnskey(zone, auth_ip)
    remarks = {}
    remarks['has_dnskey'] = has_dnskey

    # result_json['dns']['remarks'] = remarks

    result_json['dns']['evaluated_on'] = { '$date': datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")}

    # TODO: sources
    # TODO: ttls

    """ RDAP DATA """

    whoisit.bootstrap()
    result_json['rdap'] = _get_rdap(domain)

    result_json['rdap']['last_changed_date'] = { '$date': result_json['rdap']['last_changed_date'] }
    result_json['rdap']['registration_date'] = { '$date': result_json['rdap']['registration_date'] }
    result_json['rdap']['expiration_date'] = { '$date': result_json['rdap']['expiration_date'] }
 
    """ TLS DATA """

    proc = subprocess.run(
        [f'echo {domain} | {str(ZGRAB2)} http --max-redirects=1 --endpoint="{url.split(domain, 1)[1]}"', 'http', '--help'],
        capture_output=True,
        text=True,
        shell=True
    )

    handshake_data = proc.stdout

    try:

        if handshake_data:

            handshake_data = json.loads(handshake_data)
            result_json['tls']['cipher'] = handshake_data['data']['http']['result']['response']['request']['tls_log']['handshake_log']['server_hello']['cipher_suite']['name']
            result_json['tls']['protocol'] = handshake_data['data']['http']['result']['response']['request']['tls_log']['handshake_log']['server_hello']['supported_versions']['selected_version']['name']

            certificate_data = handshake_data['data']['http']['result']['response']['request']['tls_log']['handshake_log']['server_certificates']
            root_certificate = certificate_data['certificate']

            certificates = []

            for i, cert in enumerate([root_certificate] + certificate_data['chain']):

                if i == 0:
                    certificates.append(_normalize_certificate(cert, True))
                else:
                    certificates.append(_normalize_certificate(cert, False))

            result_json['tls']['certificates'] = certificates

            result_json['tls']['count'] = len(certificates)

        else:
            print("Could not fetch TLS data (Zgrab2 Error)") 
            
    except Exception as e:
        print(e)

    """ IP DATA """

    for ip in (result_json['dns'].get('A') or []):
        result_json['ip_data'].append(_get_ip_data(ip, 'A'))

    for ip in (result_json['dns'].get('AAAA') or []):
        result_json['ip_data'].append(_get_ip_data(ip, 'AAAA'))
 

    """ EPILOGUE """
    with open('output.json', 'w') as f:
        json.dump([result_json], f, indent=4, default=_encode)


if __name__ == "__main__":
    main()
