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

# ===============================
# 1. Setup
# ===============================
# Block 1
import os
from dotenv import load_dotenv
# Load environment variables from .env file
load_dotenv()
# Block 2
import math as mt
from datetime import datetime, timezone, timedelta
# Block 3
import ijson
import pandas as pd
# Block 4
import joblib
from sklearn.preprocessing import LabelEncoder, TargetEncoder
# Block 5
import requests

from decimal import Decimal
import boto3

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

# ===============================
# 2. Feature Engineering - AI Assisted
# ===============================

# Function to extract the selected 
# Current: 35
# features from the dataset into a dictionary
def extract_features(record):
    features = {}

    # Get our label (phishing or unknown)
    features["label"] = record.get("category") or ""

    # --- Domain Features ---
    domain = record.get("domain_name") or ""
    # domain_name
    features["domain_name"] = domain
    # domain_length (phishing domains often have long/random names)
    features["domain_length"] = len(domain)
    # domain_numDigits (phishing domains often have digits to mimic legit names)
    features["domain_numDigits"] = sum(c.isdigit() for c in domain)
    # domain_entropy (randomized character distribution)
    features["domain_entropy"] = -sum(
        (domain.count(c)/len(domain)) * mt.log2(domain.count(c)/len(domain))
        for c in set(domain)
    ) if domain else 0

    def to_ts(date_obj):
        try:
            if isinstance(date_obj, dict) and "$date" in date_obj:
                return datetime.fromisoformat(date_obj["$date"].replace("+00:00", "")).timestamp()
        except Exception:
            return None
        return None

    # --- RDAP Features ---
    rdap = record.get("rdap") or {}
    # registration_date (recently registered domains are suspicious)
    features["rdap_registration_ts"] = to_ts(rdap.get("registration_date"))
    # expiration_date (short validity is suspicious)
    features["rdap_expiration_ts"] = to_ts(rdap.get("expiration_date"))
    # registrar name (cheap registrars are more common in phishing)
    entities = rdap.get("entities") or {}
    registrars = entities.get("registrar") or [{}]
    features["rdap_registrar"] = registrars[0].get("name", "")
    # TODO: add today's date for empirical data
    # evaluated_on (timestamp when data was evaluated)
    evaluated_on = record.get("evaluated_on") or {}
    eval_ts = to_ts(evaluated_on)

    # --- Derived RDAP Features ---
    reg_ts = features["rdap_registration_ts"]
    exp_ts = features["rdap_expiration_ts"]
    last_changed_ts = to_ts(rdap.get("last_changed_date"))
    # rdap_domainAge (group age since domain registration)
    if eval_ts and reg_ts:
        days = (eval_ts - reg_ts) / 86400
        # Week
        if days <= 7:
            features["rdap_domainAge"] = 1
        # Month
        elif days <= 30:
            features["rdap_domainAge"] = 2
        # Year
        elif days <= 365:
            features["rdap_domainAge"] = 3
        # Older
        else:
            features["rdap_domainAge"] = 4
    else:
        features["rdap_domainAge"] = None
    # rdap_timeToExpiry (group time until domain’s registration expires)
    if eval_ts and exp_ts:
        features["rdap_timeToExpiry"] = (exp_ts - eval_ts) / 86400
        # Week
        if days <= 7:
            features["rdap_timeToExpiry"] = 1
        # Month
        elif days <= 30:
            features["rdap_timeToExpiry"] = 2
        # Year
        elif days <= 365:
            features["rdap_timeToExpiry"] = 3
        # More
        else:
            features["rdap_timeToExpiry"] = 4
    else:
        features["rdap_timeToExpiry"] = None
    # rdap_recentUpdate_flag (True if updated within 6 months)
    if eval_ts and last_changed_ts:
        features["rdap_recentUpdate_flag"] = (eval_ts - last_changed_ts) <= 180 * 86400
    else:
        features["rdap_recentUpdate_flag"] = False
    # rdap_status_clientHold_flag (True if domain is on hold)
    status_list = rdap.get("status", [])
    features["rdap_status_clientHold_flag"] = any(
        "clientHold" in s or "serverHold" in s for s in status_list
    )

    # --- DNS Features ---
    dns = record.get("dns") or {}
    # A_count (number of IPv4 addresses)
    features["dns_A_count"] = len(dns.get("A") or [])
    # AAAA_count (number of IPv6 addresses)
    features["dns_AAAA_count"] = len(dns.get("AAAA") or [])
    # MX presence (phishing often lacks mail servers)
    features["dns_MX_count"] = len(dns.get("MX") or {}) 
    # TXT presence (legit domains often have SPF/DKIM records)
    features["dns_TXT_count"] = len(dns.get("TXT") or [])
    # CNAME presence
    features["dns_has_CNAME"] = dns.get("CNAME") is not None
    # DNSSEC presence (phishing often lacks DNSSEC)
    features["dnssec_present"] = dns.get("DNSSEC") is not None
    # has_dnskey (security flag, often false for phishing)
    remarks = dns.get("remarks") or {}
    features["dnssec_has_dnskey"] = remarks.get("has_dnskey", False)

    soa = dns.get("SOA") or {}
    # refresh (unusually low refresh can be suspicious)
    features["dns_soa_refresh"] = soa.get("refresh", 0)
    # retry (no comments yet)
    features["dns_soa_retry"] = soa.get("retry", 0)
    # expire (no comments yet)
    features["dns_soa_expire"] = soa.get("expire", 0)
    # dns_NS_count (number of NS records)
    features["dns_NS_count"] = len(dns.get("NS") or {}) 
    # dns_contains_SPF_flag (True if TXT contains SPF policy)
    txt_records = dns.get("TXT") or []
    if isinstance(txt_records, list):
        features["dns_contains_SPF_flag"] = any(
            isinstance(txt, str) and "v=spf1" in txt.lower() for txt in txt_records
        )
    else:
        features["dns_contains_SPF_flag"] = False
    # TODO: missing; dns_min_TTL (minimum DNS TTL value)
    ttls = dns.get("ttls") or {}
    features["dns_min_TTL"] = min(ttls.values()) if ttls else 0

    # mismatch_ns_rdap_flag (True if NS from DNS differs from RDAP)
    rdap_ns = set([ns.lower() for ns in rdap.get("nameservers", [])])
    dns_ns = set([ns.lower() for ns in (dns.get("NS") or {}).keys()])
    features["mismatch_ns_rdap_flag"] = bool(rdap_ns and dns_ns and not (rdap_ns & dns_ns))

    # --- IP data / Hosting example Features ---
    ip_data = record.get("ip_data") or []
    if ip_data:
        asns = [i.get("asn", {}).get("as_org", "") for i in ip_data if i.get("asn")]
        countries = [i.get("geo", {}).get("country", "") for i in ip_data if i.get("geo")]

        # distinct_ASN_count (phishing often uses diverse/shady ASNs)
        features["distinct_asn_count"] = len(set(asns))
        # distinct_country_count (phishing often mismatches claimed region)
        features["distinct_country_count"] = len(set(countries))

        first_ip = ip_data[0] or {}
        # asn and geo from first IP
        asn = first_ip.get("asn") or {}
        geo = first_ip.get("geo") or {}
        # first_ip_asn (check for hosting ASN, e.g., Cloudflare vs shady ISPs)
        features["asn_org"] = asn.get("as_org", "")
        # TODO: known_asn (boolean features for known good ASNs)
        # first_ip_geo_country (check for hosting country)
        features["geo_country"] = geo.get("country", "")

    else:
        features["distinct_asn_count"] = 0
        features["distinct_country_count"] = 0
        features["asn_org"] = ""
        features["geo_country"] = ""

    # --- TLS Features ---
    tls = record.get("tls") or {}
    # protocol (e.g., TLSv1.3 is common)
    features["tls_protocol"] = tls.get("protocol", "")
    certs = tls.get("certificates") or []
    features["cert_chain_length"] = len(certs)

    if certs:
        # Aggregated Validity: Get the shortest validity in the whole chain
        valid_lengths = [c.get("valid_len", 0) for c in certs if c.get("valid_len")]
        # valid_len (short cert validity = suspicious)
        features["tls_min_cert_valid_len"] = min(valid_lengths) if valid_lengths else 0
        
        # Check for Self-Signed (Leaf is Root)
        features["is_self_signed"] = certs[0].get("common_name") == certs[-1].get("common_name")

        # Get leaf certificate details
        cert = certs[0] or {}
        # organization (e.g., Let’s Encrypt vs premium CAs)
        features["tls_cert_org"] = cert.get("organization", "")
        # san_count (multiple wildcards, SANs can indicate phishing)
        san_exts = [
            ext for ext in cert.get("extensions") or []
            if ext.get("name") == "subjectAltName"
        ]

        if san_exts:
            features["tls_san_count"] = len(san_exts[0].get("value", "").split(","))
        else:
            features["tls_san_count"] = 0
        # is_root (whether cert chain is valid/trusted)
        features["tls_cert_is_root"] = cert.get("is_root", False)
    else:
        features["is_self_signed"] = True
        features["tls_min_cert_valid_len"] = 0
        features["tls_cert_org"] = ""
        features["tls_san_count"] = 0
        features["tls_cert_is_root"] = False
    return features

# Advance future features 
# Keyword hunting in all tls certificate SANs (san_has_security_keywords)
# If registrant country is different from IP geo country (geo_mismatch)

def lambda_handler(event, context):

    if len(sys.argv)!= 2:
        raise ValueError('Incorrect number of arguments was given.')


    result_json = {}

    # url = sys.argv[1]
    url = event['body']
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


    """ AWS STUFF """
    # Get AWS URL from environment variable
    aws_url = os.getenv('AWS_URL')
    # Get the sample JSON path
    sample_path = "./data/Feb2/output1.json"
    # Get the encoders prefix path
    encoders_prefix = "./encoders/Jan27"

    # ===============================
    # 3. Read data + Apply feature extraction
    # ===============================

    # Read data from sample JSON to see the features extracted
    sample_records = []
    with open(sample_path, 'r', encoding='utf-8') as file:
        for item in ijson.items(file, 'item'):
            sample_records.append(extract_features(item))

    input = pd.json_normalize(sample_records)

    X_target_encoders = joblib.load(f"{encoders_prefix}/target_encoders.joblib")
    X_label_encoders = joblib.load(f"{encoders_prefix}/label_encoders.joblib")

    def apply_target_encoders(X_new, encoders):
        X_new = X_new.copy()

        for col, encoder in encoders.items():
            X_new[col] = X_new[col].astype("category")
            X_new[col] = encoder.transform(X_new[[col]])

        return X_new

    def apply_label_encoders(X_new, encoders):
        X_new = X_new.copy()

        for col, encoder in encoders.items():
            X_new[col] = encoder.transform(X_new[col].astype(str))

        return X_new

    input_encoded = apply_target_encoders(input, X_target_encoders)
    input_encoded = apply_label_encoders(input_encoded, X_label_encoders)

    # Convert input_encoded DataFrame to comma-separated string
    # Taking the first row and converting to CSV format
    input_string = ",".join(input_encoded.iloc[0].astype(str).values)

    # Format the output: drop first two data points and replace None with empty string
    input_list = input_string.split(',')
    # Drop first two elements
    input_list = input_list[2:]
    # Replace 'None' with empty string
    input_list = ['' if val == 'None' else val for val in input_list]
    # Rejoin as comma-separated string
    input_string = ",".join(input_list)

    # ===============================
    # 5. Send data to API
    # ===============================

    # Define the JSON data to be sent
    # Example: 13,2,3.180832987205441,1057795969.0,1720570369.0,0.691244836372824,7469.716872962962,201.2831270370384,0,0,1,0,0,0,0,0,0,0,0,0,0,0,1,1,1.0,0.9233829790536662,0,0.9784475747064278,31535999,2,0
    json_data = {
        "input": input_string
    }

    # Send the JSON data to the API
    response = requests.post(aws_url, json=json_data)

    # Print the response from the API
    # 1 is safe, 0 is phishing
    print(response.status_code)
    result = response.json()

    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table("Url-Reputation")

    def store_url_reputation(url: str, confidence_score: float):
        table.put_item(
            Item={
                "url": url,
                "confidence_score": Decimal(str(confidence_score))
            }
        )

    store_url_reputation(
        url=url,
        confidence_score=result['prediction']
    )

#if __name__ == "__main__":
#    main()
