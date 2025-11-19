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

            for i, rdata in enumerate(answer):
                record_info[i] = rdata.to_text()
        
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
