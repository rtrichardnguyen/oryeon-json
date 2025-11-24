import sys
import dns.resolver
import dns.name
from urllib.parse import urlparse
import json



DNS_RECORDS = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']

def main():

    if len(sys.argv)!= 2:
        raise ValueError('Incorrect number of arguments was given.')


    result_json = {}

    url = sys.argv[1]
    domain = urlparse(url).netloc

    if not domain:
        raise ValueError('Incorrect URL value was given.')

    result_json['url'] = url
    result_json['domain_name'] = domain 
    result_json['dns'] = {}
    result_json['ip_data'] = {}
    result_json['rdap'] = {}
    result_json['tls'] = {}


    """ DNS DATA """

    for record in DNS_RECORDS:

        try:
            record_info = {}
            answer = dns.resolver.resolve(domain, record)

            match record:

                case 'A' | 'AAAA':

                    for i, rdata in enumerate(answer):
                        record_info[i] = rdata.to_text()

                case 'CNAME':

                    related_ips = []

                    cname_rdata = answer[0].to_text()

                    record_info["value"] = cname_rdata
                    cname_answer_A = dns.resolver.resolve(cname_rdata, "A")
                    cname_answer_AAAA = dns.resolver.resolve(cname_rdata, "AAAA")

                    for rdata_A in (cname_answer_A):
                        ttl = str(cname_answer_A.ttl)
                        value = str(rdata_A.address)

                        related_ips.append({'ttl': ttl, 'value': value})

                    record_info["related_ips"] = related_ips

                    for rdata_AAAA in (cname_answer_AAAA):
                        ttl = str(cname_answer_AAAA.ttl)
                        value = str(rdata_AAAA.address)

                        related_ips.append({'ttl': ttl, 'value': value})

                    record_info["related_ips"] = related_ips

                       
                case 'MX':
                    pass
                case 'NS':

                    for i, rdata in enumerate(answer):
                        #rdata.address for ip | answer.rrset.ttl for ttl
                        ip_dict = {}
                        related_ips = []

                        nameserver = rdata.to_text()

                        ip_answer_A = dns.resolver.resolve(nameserver, "A")
                        ip_answer_AAAA = dns.resolver.resolve(nameserver, "AAAA")

                        for rdata_A in ip_answer_A:

                            ttl = str(ip_answer_A.ttl)
                            value = str(rdata_A.address)

                            related_ips.append({'ttl': ttl, 'value': value})

                        for rdata_AAAA in ip_answer_AAAA:

                            ttl = str(ip_answer_AAAA.ttl)
                            value = str(rdata_AAAA.address)

                            related_ips.append({'ttl': ttl, 'value': value})

                        ip_dict['related_ips'] = related_ips
                        record_info[nameserver] = ip_dict

                case 'TXT':
                    pass
                case 'SOA':
                    pass
        
        except dns.resolver.LifetimeTimeout:
            print(f"LifetimeTimeout ERROR '{record}': Timeout while resolving DNS data.")

        except dns.resolver.NXDOMAIN:
            print(f"NXDOMAIN ERROR '{record}': Query name does not exist.")

        except dns.resolver.YXDOMAIN:
            print(f"YXDOMAIN ERROR '{record}': Query name is too long after DNAME substitution.")

        except dns.resolver.NoAnswer:
            print(f"NoAnswer ERROR '{record}': raise_on_no_answer is True and the query name exists but has no RRset of the desired type and class.")

        except dns.resolver.NoNameservers:
            print(f"NoNameservers ERROR '{record}': No non-broken nameservers are available to resolve the DNS data.")

        finally:
            result_json['dns'][record] = None if not record_info else record_info
    
    print(json.dumps(result_json, indent=4))


if __name__ == "__main__":
    main()
