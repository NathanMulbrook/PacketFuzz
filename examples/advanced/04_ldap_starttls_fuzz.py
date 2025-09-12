#!/usr/bin/env python3
"""
LDAP StartTLS Fuzzing Example

Simplified LDAP StartTLS fuzzing using framework features and Scapy's LDAP support.
Fuzzes TLS traffic after StartTLS negotiation.
"""

from scapy.asn1fields import *
from scapy.asn1packet import ASN1_Packet
from scapy.asn1.asn1 import ASN1_Codecs
from scapy.layers.inet import TCP
from scapy.layers.ldap import LDAP, LDAPOID, ASN1_Class_LDAP, LDAPResult
from scapy.layers.tls.all import TLS, TLSApplicationData, TLSClientHello

from packetfuzz.fuzzing_framework import FuzzingCampaign, CallbackResult, CampaignContext
from packetfuzz.sockets.managed_tcp_socket import ManagedTCPConfig


# --- Custom Scapy LDAP ExtendedRequest for StartTLS ---
# This is necessary because Scapy's built-in LDAP layer has ExtendedResponse
# but is missing ExtendedRequest (tag 119) needed for StartTLS.

class LDAP_ExtendedRequest(ASN1_Packet):
    name = "LDAP Extended Request"
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        LDAPOID("requestName", "1.3.6.1.4.1.1466.20037"),  # StartTLS OID
        ASN1F_optional(ASN1F_STRING("requestValue", None)),
        implicit_tag=ASN1_Class_LDAP.ExtendedRequest,
    )

# Add the missing ExtendedRequest to LDAP's protocol choices
# Tag 119 is the official LDAP ExtendedRequest tag per RFC 4511
for field in LDAP.fields_desc:
    if field.name == "protocolOp":
        field.choices[119] = LDAP_ExtendedRequest
        break


class LDAPStartTLSCampaign(FuzzingCampaign):
    """LDAP StartTLS TLS Application Data fuzzing."""
    
    name = "LDAP StartTLS TLS Fuzzing"
    socket_config = ManagedTCPConfig(target="127.0.0.1", port=389)
    iterations = 10
    output_pcap = "ldap_starttls_fuzz.pcap"
    verbose = True
    output_network = False
    
    # TLS Application Data with LDAP search filter - framework will fuzz this
    packet = TLS() / TLSApplicationData(data=b"(objectClass=*)")

    def __init__(self):
        super().__init__()
        self.tls_negotiated = False

    def pre_send_callback(self, context: CampaignContext, packet):
        """Perform StartTLS handshake once before fuzzing."""
        if not self.tls_negotiated:
            if not context.fuzz_socket:
                self.tls_negotiated = True
                return CallbackResult.SUCCESS
                
            raw_socket = context.fuzz_socket.raw
            
            # Send StartTLS request
            starttls_req = LDAP(messageID=1, protocolOp=LDAP_ExtendedRequest(requestName="1.3.6.1.4.1.1466.20037"))
            raw_socket.send(bytes(starttls_req))
            raw_socket.recv(1024)
            
            # Complete TLS handshake
            client_hello = TLS() / TLSClientHello()
            raw_socket.send(bytes(client_hello))
            raw_socket.recv(4096)
            
            self.tls_negotiated = True

        return CallbackResult.SUCCESS


class LDAPStartTLSHandshakeFuzz(FuzzingCampaign):
    """LDAP StartTLS TLS handshake fuzzing."""
    
    name = "LDAP StartTLS Handshake Fuzzing" 
    socket_config = ManagedTCPConfig(target="127.0.0.1", port=389)
    iterations = 5
    output_pcap = "ldap_starttls_handshake_fuzz.pcap"
    verbose = True
    output_network = False
    
    # TLS ClientHello - framework will fuzz the handshake parameters
    packet = TLS() / TLSClientHello()

    def __init__(self):
        super().__init__()
        self.starttls_sent = False

    def pre_send_callback(self, context: CampaignContext, packet):
        """Send StartTLS request once before fuzzing handshake."""
        if not self.starttls_sent:
            if not context.fuzz_socket:
                self.starttls_sent = True
                return CallbackResult.SUCCESS
                
            starttls_req = LDAP(messageID=1, protocolOp=LDAP_ExtendedRequest(requestName="1.3.6.1.4.1.1466.20037"))
            context.fuzz_socket.raw.send(bytes(starttls_req))
            context.fuzz_socket.raw.recv(1024)
            self.starttls_sent = True

        return CallbackResult.SUCCESS


CAMPAIGNS = [LDAPStartTLSCampaign, LDAPStartTLSHandshakeFuzz]
