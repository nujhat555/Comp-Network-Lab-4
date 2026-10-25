"""DNS test client for the DNS Server assignment.

Install dnspython before running this file:
    python -m pip install dnspython

The local DNS server must be running at 127.0.0.1 on the default DNS port (53).
"""

import dns.exception
import dns.resolver

# 127.0.0.1 is the loopback address used to reach a server on this computer.
local_host_ip = "127.0.0.1"
# Google Public DNS.
real_name_server = "8.8.8.8"

# Use the same domain names as the DNS Server assignment.
domainList = [
    "example.com.",
    "safebank.com.",
    "google.com.",
    "nyu.edu.",
    "legitsite.com.",
]


def query_local_dns_server(domain, question_type):
    """Return the first answer from the local DNS server."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [local_host_ip]
    answers = resolver.resolve(domain, question_type)
    return answers[0].to_text()


def query_dns_server(domain, question_type):
    """Return the first answer from the public DNS server."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [real_name_server]
    answers = resolver.resolve(domain, question_type)
    return answers[0].to_text()


def compare_dns_servers(domains, question_type):
    """Return True if both DNS servers resolve every domain identically."""
    for domain_name in domains:
        try:
            local_ip_address = query_local_dns_server(domain_name, question_type)
            public_ip_address = query_dns_server(domain_name, question_type)
        except (dns.exception.DNSException, OSError):
            return False

        if local_ip_address != public_ip_address:
            return False
    return True


def local_external_DNS_output(question_type):
    """Print results from the local and public DNS servers."""
    print("Local DNS Server")
    for domain_name in domainList:
        try:
            ip_address = query_local_dns_server(domain_name, question_type)
            print(f"The IP address of {domain_name} is {ip_address}")
        except (dns.exception.DNSException, OSError) as error:
            print(f"Could not resolve {domain_name} locally: {error}")

    print("\nPublic DNS Server")
    for domain_name in domainList:
        try:
            ip_address = query_dns_server(domain_name, question_type)
            print(f"The IP address of {domain_name} is {ip_address}")
        except (dns.exception.DNSException, OSError) as error:
            print(f"Could not resolve {domain_name} publicly: {error}")


def exfiltrate_info(domain, question_type):
    """Part 2 testing hook: query the local DNS server and return its answer."""
    return query_local_dns_server(domain, question_type)


if __name__ == "__main__":
    question_type = "A"

    local_external_DNS_output(question_type)
    same_answers = compare_dns_servers(domainList, question_type)
    print(f"Do both DNS servers return the same answers? {same_answers}")
