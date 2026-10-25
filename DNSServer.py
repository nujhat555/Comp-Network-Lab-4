import ast
import base64
import hashlib
import os
import signal
import socket
import sys
import threading

import dns.message
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,
    )
    key = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    return f.encrypt(input_string.encode("utf-8"))


def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data.decode("utf-8")

salt = b"Tandon"
password = "nmc9486@nyu.edu"
input_string = "AlwaysWatching"
encrypted_value = encrypt_with_aes(input_string, password, salt)
decrypted_value = decrypt_with_aes(encrypted_value, password, salt)


def generate_sha256_hash(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode("utf-8"))
    return sha256_hash.hexdigest()


dns_records = {
    "example.com.": {
        dns.rdatatype.A: "192.168.1.101",
        dns.rdatatype.AAAA: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        dns.rdatatype.MX: [(10, "mail.example.com.")],
        dns.rdatatype.CNAME: "www.example.com.",
        dns.rdatatype.NS: "ns.example.com.",
        dns.rdatatype.TXT: ("This is a TXT record",),
        dns.rdatatype.SOA: (
            "ns1.example.com.",
            "admin.example.com.",
            2023081401,
            3600,
            1800,
            604800,
            86400,
        ),
    },
    "safebank.com.": {
        dns.rdatatype.A: "192.168.1.102",
    },
    "google.com.": {
        dns.rdatatype.A: "192.168.1.103",
    },
    "legitsite.com.": {
        dns.rdatatype.A: "192.168.1.104",
    },
    "yahoo.com.": {
        dns.rdatatype.A: "192.168.1.105",
    },
    "nyu.edu.": {
        dns.rdatatype.A: "192.168.1.106",
        dns.rdatatype.TXT: str(encrypted_value),
        dns.rdatatype.MX: [(10, "mxa-00256a01.gslb.pphosted.com.")],
        dns.rdatatype.AAAA: "2001:0db8:85a3:0000:0000:8a2e:0373:7312",
        dns.rdatatype.NS: "ns1.nyu.edu.",
    },
}


def _quoted_txt(value):
    value = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{value}"'


def _build_rdata_list(qtype, answer_data):
    if qtype == dns.rdatatype.MX:
        return [
            MX(dns.rdataclass.IN, dns.rdatatype.MX, preference, mail_server)
            for preference, mail_server in answer_data
        ]

    if qtype == dns.rdatatype.SOA:
        mname, rname, serial, refresh, retry, expire, minimum = answer_data
        return [
            SOA(
                dns.rdataclass.IN,
                dns.rdatatype.SOA,
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            )
        ]

    if qtype == dns.rdatatype.TXT:
        values = [answer_data] if isinstance(answer_data, str) else answer_data
        return [
            dns.rdata.from_text(
                dns.rdataclass.IN, qtype, _quoted_txt(value)
            )
            for value in values
        ]

    values = [answer_data] if isinstance(answer_data, str) else answer_data
    return [
        dns.rdata.from_text(dns.rdataclass.IN, qtype, value)
        for value in values
    ]


def run_dns_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 53))

    try:
        while True:
            data, addr = server_socket.recvfrom(1024)
            try:
                request = dns.message.from_wire(data)
                response = dns.message.make_response(request)
                if not request.question:
                    response.set_rcode(dns.rcode.FORMERR)
                else:
                    question = request.question[0]
                    qname = question.name.to_text().lower()
                    qtype = question.rdtype

                    if qname not in dns_records:
                        response.set_rcode(dns.rcode.NXDOMAIN)
                    elif qtype in dns_records[qname]:
                        answer_data = dns_records[qname][qtype]
                        rrset = dns.rrset.RRset(
                            question.name, dns.rdataclass.IN, qtype
                        )
                        for rdata in _build_rdata_list(qtype, answer_data):
                            rrset.add(rdata, 60)
                        response.answer.append(rrset)

                    # Mark answers from this local server as authoritative.
                    response.flags |= 1 << 10

                server_socket.sendto(response.to_wire(), addr)
            except Exception as error:
                print(f"Could not process DNS request: {error}")

    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        server_socket.close()


def run_dns_server_user():
    print("Input 'q' and hit 'enter' to quit")
    print("DNS server is running...")

    def user_input():
        while True:
            command = input()
            if command.lower() == "q":
                print("Quitting...")
                os.kill(os.getpid(), signal.SIGINT)

    input_thread = threading.Thread(target=user_input, daemon=True)
    input_thread.start()
    run_dns_server()


if __name__ == "__main__":
    run_dns_server_user()
