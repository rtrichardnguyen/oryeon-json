import sys, json, re, ssl, socket, whoisit
import dns.resolver
import dns.name
from urllib.parse import urlparse
from ipwhois import IPWhois
from datetime import datetime

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
    # TODO: asn
    # TODO: geo

    return ip_data_dict

def _encode(obj):

    if isinstance(obj, datetime):
        return obj.isoformat() + 'Z'

def main():

    if len(sys.argv)!= 2:
        raise ValueError('Incorrect number of arguments was given.')


    result_json = {}

    url = sys.argv[1]
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

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

                    record_info[record] = ips

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
    # TODO: ttls
    # TODO: remarks


    """ RDP DATA """

    whoisit.bootstrap()
    result_json['rdap'] = _get_rdap(domain)


    """ TLS DATA """


    """ IP DATA """

    for ip in result_json['dns']['A']['A']:
        result_json['ip_data'].append(_get_ip_data(ip, 'A'))

    for ip in result_json['dns']['AAAA']['AAAA']:
        result_json['ip_data'].append(_get_ip_data(ip, 'AAAA'))
 

    """ EPILOGUE """
    with open('output.json', 'w') as f:
        json.dump(result_json, f, indent=4, default=_encode)


if __name__ == "__main__":
    main()
