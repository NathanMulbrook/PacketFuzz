#!/usr/bin/env python3
"""
Default Dictionary Mappings for PacketFuzz

This module provides advanced dictionary mappings for common network protocol fields.
Features:
- Macros for reusable dictionary lists
- Type, name, and property-based mapping
- Default: combine all matching dictionaries
- Optional override for exclusive dictionary selection
- Utility functions for dictionary resolution and macro expansion

Usage:
- Use FIELD_ADVANCED_DICTIONARIES for exclusive field-to-dictionary mappings
- Use MACROS to define reusable dictionary lists
- Use FIELD_TYPE_DICTIONARIES and FIELD_NAME_DICTIONARIES for standard mappings
- Call manager.get_field_dictionaries(packet, field_name) to get all applicable dictionaries
"""


from typing import Optional, List


# Macros for reusable dictionary lists
# Expanded MACROS for protocol, attack, encoding, and context-specific lists
MACROS = {
    # Generic types
    "string": [
        "fuzzdb/attack/unicode/naughty-unicode.txt",
        "fuzzdb/attack/unicode/specialchars.txt",
        "fuzzdb/attack/unicode/emoji.txt",
        "fuzzdb/attack/unicode/right-to-left.txt",
        "fuzzdb/attack/unicode/corrupted.txt",
        "fuzzdb/attack/unicode/upsidedown.txt",
        "fuzzdb/attack/unicode/japanese-emoticon.txt",
        "fuzzdb/attack/unicode/two-byte-chars.txt",
        "fuzzdb/attack/unicode/regionalindicators.txt",
        "fuzzdb/control-chars/NullByteRepresentations.txt",
        "fuzzdb/wordlists-misc/wordlist-alphanumeric-case.txt",
        "fuzzdb/wordlists-misc/accidental_profanity.txt",
        "fuzzdb/wordlists-misc/us_cities.txt",
        "fuzzdb/wordlists-misc/wordlist-dna.txt",
        "fuzzdb/wordlists-misc/wordlist-dictionary.txt",
        "fuzzdb/wordlists-misc/wordlist-english.txt",
        "fuzzdb/wordlists-misc/wordlist-uk.txt",
        "fuzzdb/wordlists-misc/wordlist-usa.txt"
    ],
    "numeric": [
        "fuzzdb/wordlists-misc/numeric.txt",
        "fuzzdb/attack/integer-overflow/integer-overflows.txt",
        "fuzzdb/wordlists-misc/wordlist-numeric.txt"
    ],
    "payload": [
        "fuzzdb/attack/all-attacks/all-attacks-unix.txt",
        "fuzzdb/attack/all-attacks/all-attacks-xplatform.txt",
        "fuzzdb/attack/all-attacks/all-attacks-win.txt",
        "fuzzdb/attack/control-chars/terminal-escape-codes.txt",
        "fuzzdb/attack/all-attacks/all-attacks-web.txt",
        "fuzzdb/attack/all-attacks/all-attacks-windows.txt"
    ],
    "address": [
        "fuzzdb/attack/ip/localhost.txt",
        "fuzzdb/wordlists-misc/resolvers.txt",
        "fuzzdb/wordlists-misc/wordlist-alphanumeric-case.txt",
        "fuzzdb/attack/ip/ip-addresses.txt",
        "fuzzdb/attack/ip/ip-addresses-v6.txt"
    ],
    "protocol": [
        "fuzzdb/attack/http-protocol/http-protocol-methods.txt",
        "fuzzdb/attack/http-protocol/http-request-header-field-names.txt",
        "fuzzdb/attack/http-protocol/http-response-header-field-names.txt",
        "fuzzdb/attack/http-protocol/http-header-cache-poison.txt",
        "fuzzdb/attack/http-protocol/crlf-injection.txt"
    ],
    "useragent": [
        "fuzzdb/attack/http-protocol/user-agents.txt",
        "fuzzdb/discovery/UserAgent/UserAgentListCommon.txt",
        "fuzzdb/discovery/UserAgent/UserAgents.txt"
    ],
    "email": [
        "fuzzdb/attack/email/valid-email-addresses.txt",
        "fuzzdb/attack/email/invalid-email-addresses.txt",
        "fuzzdb/wordlists-misc/wordlist-email.txt"
    ],
    "auth_user": [
        "fuzzdb/wordlists-user-passwd/unix-os/db-user-list.txt",
        "fuzzdb/wordlists-user-passwd/names/namelist.txt",
        "fuzzdb/wordlists-user-passwd/db2/db2_default_user.txt",
        "fuzzdb/wordlists-user-passwd/oracle/oracle_logins.txt",
        "fuzzdb/wordlists-user-passwd/tomcat/tomcat_mgr_default_users.txt",
        "fuzzdb/wordlists-user-passwd/oracle/oracle_login_user.txt"
    ],
    "auth_pass": [
        "fuzzdb/wordlists-user-passwd/passwds/john.txt",
        "fuzzdb/wordlists-user-passwd/passwds/phpbb.txt",
        "fuzzdb/wordlists-user-passwd/passwds/twitter.txt",
        "fuzzdb/wordlists-user-passwd/passwds/weaksauce.txt",
        "fuzzdb/wordlists-user-passwd/oracle/oracle_passwords.txt",
        "fuzzdb/wordlists-user-passwd/tomcat/tomcat_mgr_default_pass.txt"
    ],
    "file_name": [
        "fuzzdb/attack/file-upload/invalid-filenames-linux.txt",
        "fuzzdb/attack/file-upload/invalid-filenames-microsoft.txt",
        "fuzzdb/attack/file-upload/invalid-filenames-windows.txt"
    ],
    "file_ext": [
        "fuzzdb/attack/file-upload/alt-extensions-php.txt",
        "fuzzdb/attack/file-upload/alt-extensions-asp.txt",
        "fuzzdb/attack/file-upload/alt-extensions-jsp.txt",
        "fuzzdb/attack/file-upload/alt-extensions-coldfusion.txt",
        "fuzzdb/attack/file-upload/alt-extensions-pl.txt"
    ],
    "dns_name": [
        "fuzzdb/discovery/dns/alexaTop1mAXFRcommonSubdomains.txt",
        "fuzzdb/discovery/dns/dnsmapCommonSubdomains.txt",
        "fuzzdb/discovery/dns/gTLD.txt",
        "fuzzdb/discovery/dns/CcTLD.txt"
    ],
    "xpath": [
        "fuzzdb/attack/xpath/xpath-injection.txt"
    ],
    "ldap": [
        "fuzzdb/attack/ldap/ldap-injection.txt"
    ],
    "json": [
        "fuzzdb/attack/json/JSON_Fuzzing.txt",
        "fuzzdb/attack/business-logic/DebugParams.Json.fuzz.txt"
    ],
    "xml": [
        "fuzzdb/attack/xml/xml-attacks.txt"
    ],
    "os_command": [
        "fuzzdb/attack/os-cmd-execution/command-execution-unix.txt",
        "fuzzdb/attack/os-cmd-execution/Commands-Linux.txt",
        "fuzzdb/attack/os-cmd-execution/Commands-Windows.txt",
        "fuzzdb/attack/os-cmd-execution/Commands-OSX.txt",
        "fuzzdb/attack/os-cmd-execution/shell-operators.txt",
        "fuzzdb/attack/os-cmd-execution/shell-delimiters.txt"
    ],
    "sql_injection": [
        "fuzzdb/attack/sql-injection/detect/Generic_SQLI.txt",
        "fuzzdb/attack/sql-injection/detect/MySQL.txt",
        "fuzzdb/attack/sql-injection/detect/Oracle.txt",
        "fuzzdb/attack/sql-injection/detect/PostgreSQL.txt",
        "fuzzdb/attack/sql-injection/detect/SQLite.txt"
    ],
    "xss": [
        "fuzzdb/attack/xss/xss-rsnake.txt",
        "fuzzdb/attack/xss/XSSPolyglot.txt",
        "fuzzdb/attack/xss/xss-payload-list.txt"
    ],
    "unicode": [
        "fuzzdb/attack/unicode/naughty-unicode.txt",
        "fuzzdb/attack/unicode/specialchars.txt",
        "fuzzdb/attack/unicode/emoji.txt",
        "fuzzdb/attack/unicode/right-to-left.txt",
        "fuzzdb/attack/unicode/corrupted.txt",
        "fuzzdb/attack/unicode/upsidedown.txt",
        "fuzzdb/attack/unicode/japanese-emoticon.txt",
        "fuzzdb/attack/unicode/two-byte-chars.txt",
        "fuzzdb/attack/unicode/regionalindicators.txt"
    ],
    "traversal": [
        "fuzzdb/attack/path-traversal/path-traversal-windows.txt",
        "fuzzdb/attack/path-traversal/traversals-8-deep-exotic-encoding.txt",
        "fuzzdb/attack/path-traversal/path-traversal-unix.txt"
    ],
    "shell": [
        "fuzzdb/attack/os-cmd-execution/shell-operators.txt",
        "fuzzdb/attack/os-cmd-execution/shell-delimiters.txt"
    ],
    # Add more as discovered
}

# Type-based field mappings
FIELD_TYPE_DICTIONARIES = {
    "string": ["@string"],
    "numeric": ["@numeric"],
    "payload": ["@payload"],
    "address": ["@address"],
    "protocol": ["@protocol"],
    "email": ["@email"],
    "useragent": ["@useragent"],
    "auth_user": ["@auth_user"],
    "auth_pass": ["@auth_pass"],
    "file_name": ["@file_name"],
    "file_ext": ["@file_ext"],
    "dns_name": ["@dns_name"],
    "xpath": ["@xpath"],
    "ldap": ["@ldap"],
    "json": ["@json"],
    "xml": ["@xml"],
    "os_command": ["@os_command"],
    "sql_injection": ["@sql_injection"],
    "xss": ["@xss"],
    "unicode": ["@unicode"],
    "traversal": ["@traversal"],
    "shell": ["@shell"],
    # ...more as discovered
}

# Name-based field mappings
FIELD_NAME_DICTIONARIES = {
    "TCP.dport": [
        "@numeric",
        "fuzzdb/wordlists-misc/common-http-ports.txt"
    ],
    "TCP.sport": [
        "@numeric",
        "fuzzdb/wordlists-misc/common-http-ports.txt"
    ],
    "TCP.flags": [
        "@numeric"
    ],
    "UDP.dport": [
        "@numeric",
        "fuzzdb/wordlists-misc/common-http-ports.txt"
    ],
    "UDP.sport": [
        "@numeric",
        "fuzzdb/wordlists-misc/common-http-ports.txt"
    ],
    "IP.dst": [
        "@address",
        "fuzzdb/attack/ip/localhost.txt",
        "fuzzdb/wordlists-misc/resolvers.txt"
    ],
    "IP.src": [
        "@address",
        "fuzzdb/attack/ip/localhost.txt"
    ],
    "IP.ttl": [
        "@numeric"
    ],
    "IP.tos": [
        "@numeric"
    ],
    "IP.frag": [
        "@numeric"
    ],
    "ICMP.type": [
        "@numeric"
    ],
    "ICMP.code": [
        "@numeric"
    ],
    "DNS.id": [
        "@numeric"
    ],
    "DNSQR.qname": [
        "@dns_name",
        "@string",
        "fuzzdb/discovery/dns/alexaTop1mAXFRcommonSubdomains.txt",
        "fuzzdb/discovery/dns/dnsmapCommonSubdomains.txt",
        "fuzzdb/attack/unicode/naughty-unicode.txt",
        "fuzzdb/attack/unicode/specialchars.txt"
    ],
    "DNSQR.qtype": [
        "@numeric"
    ],
    "DNS.qd": [
        "fuzzdb/discovery/dns/alexaTop1mAXFRcommonSubdomains.txt"
    ],
    "Raw.load": [
        "@payload",
        "@xss",
        "@sql_injection",
        "fuzzdb/attack/http-protocol/http-protocol-methods.txt",
        "fuzzdb/attack/http-protocol/user-agents.txt",
        "fuzzdb/attack/http-protocol/http-request-header-field-names.txt",
        "fuzzdb/attack/xss/xss-rsnake.txt",
        "fuzzdb/attack/xss/XSSPolyglot.txt",
        "fuzzdb/attack/sql-injection/detect/Generic_SQLI.txt",
        "fuzzdb/attack/sql-injection/detect/MySQL.txt",
        "fuzzdb/attack/path-traversal/path-traversal-windows.txt",
        "fuzzdb/attack/path-traversal/traversals-8-deep-exotic-encoding.txt",
        "fuzzdb/attack/control-chars/NullByteRepresentations.txt",
        "fuzzdb/attack/format-strings/format-strings.txt"
    ],
    "Ether.dst": [
        "fuzzdb/wordlists-misc/wordlist-alphanumeric-case.txt"
    ],
    "Ether.src": [
        "fuzzdb/wordlists-misc/wordlist-alphanumeric-case.txt"
    ],
    "Ether.type": [
        "@numeric"
    ],
    "ARP.hwsrc": [
        "fuzzdb/wordlists-misc/wordlist-alphanumeric-case.txt"
    ],
    "ARP.hwdst": [
        "fuzzdb/wordlists-misc/wordlist-alphanumeric-case.txt"
    ],
    "ARP.psrc": [
        "fuzzdb/attack/ip/localhost.txt"
    ],
    "ARP.pdst": [
        "fuzzdb/attack/ip/localhost.txt"
    ],
    "ARP.op": [
        "@numeric"
    ],
    "HTTPRequest.Method": [
        "@protocol",
        "fuzzdb/attack/http-protocol/http-protocol-methods.txt"
    ],
    "HTTPRequest.Path": [
        "@string",
        "@traversal",
        "fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-files.txt",
        "fuzzdb/attack/path-traversal/path-traversal-windows.txt"
    ],
    "HTTPRequest.Http-Version": [
        "@protocol",
        "fuzzdb/attack/http-protocol/http-protocol-methods.txt"
    ],
    "HTTPRequest.User-Agent": [
        "@useragent",
        "@string",
        "fuzzdb/attack/http-protocol/user-agents.txt"
    ],
    "HTTPRequest.Host": [
        "@dns_name",
        "@string",
        "fuzzdb/discovery/dns/alexaTop1mAXFRcommonSubdomains.txt"
    ],
    "SMTP.mailfrom": [
        "@email",
        "fuzzdb/attack/email/valid-email-addresses.txt",
        "fuzzdb/attack/email/invalid-email-addresses.txt"
    ],
    "SMTP.rcptto": [
        "@email",
        "fuzzdb/attack/email/valid-email-addresses.txt",
        "fuzzdb/attack/email/invalid-email-addresses.txt"
    ],
    "LDAP.filter": [
        "@ldap",
        "@string",
        "fuzzdb/attack/ldap/ldap-injection.txt"
    ],
    "LDAP.dn": [
        "@ldap",
        "@string",
        "fuzzdb/attack/ldap/ldap-injection.txt",
        "fuzzdb/attack/unicode/naughty-unicode.txt"
    ],
    "JSON.data": [
        "@json",
        "@string",
        "fuzzdb/attack/json/JSON_Fuzzing.txt",
        "fuzzdb/attack/business-logic/DebugParams.Json.fuzz.txt"
    ],
    "XML.data": [
        "@xml",
        "@string",
        "fuzzdb/attack/xml/xml-attacks.txt",
        "fuzzdb/attack/unicode/naughty-unicode.txt"
    ],
    "XPath.query": [
        "@xpath",
        "@string",
        "fuzzdb/attack/xpath/xpath-injection.txt"
    ],
    "NoSQL.query": [
        "@string",
        "fuzzdb/attack/no-sql-injection/mongodb.txt"
    ],
    "File.name": [
        "@file_name",
        "@string",
        "fuzzdb/attack/file-upload/invalid-filenames-linux.txt",
        "fuzzdb/attack/file-upload/invalid-filenames-microsoft.txt"
    ],
    "File.extension": [
        "@file_ext",
        "@string",
        "fuzzdb/attack/file-upload/alt-extensions-php.txt",
        "fuzzdb/attack/file-upload/alt-extensions-asp.txt",
        "fuzzdb/attack/file-upload/alt-extensions-jsp.txt",
        "fuzzdb/attack/file-upload/alt-extensions-coldfusion.txt"
    ],
    "File.path": [
        "@string",
        "@traversal",
        "fuzzdb/attack/file-upload/file-ul-filter-bypass-commonly-writable-directories.txt",
        "fuzzdb/attack/path-traversal/path-traversal-windows.txt",
        "fuzzdb/attack/path-traversal/traversals-8-deep-exotic-encoding.txt"
    ],
    "HTML.attribute": [
        "@string",
        "@xss",
        "fuzzdb/attack/html_js_fuzz/html_attributes.txt",
        "fuzzdb/attack/html_js_fuzz/javascript_events.txt"
    ],
    "HTML.tag": [
        "@string",
        "@xss",
        "fuzzdb/attack/html_js_fuzz/html_tags.txt"
    ],
    "JS.event": [
        "@string",
        "@xss",
        "fuzzdb/attack/html_js_fuzz/javascript_events.txt"
    ],
    "JS.code": [
        "@string",
        "@xss",
        "fuzzdb/attack/html_js_fuzz/js_inject.txt",
        "fuzzdb/attack/html_js_fuzz/HTML5sec_Injections.txt"
    ],
    "OS.command": [
        "@os_command",
        "@string",
        "fuzzdb/attack/os-cmd-execution/command-execution-unix.txt",
        "fuzzdb/attack/os-cmd-execution/Commands-Linux.txt",
        "fuzzdb/attack/os-cmd-execution/Commands-Windows.txt",
        "fuzzdb/attack/os-cmd-execution/Commands-OSX.txt"
    ],
    "OS.shell": [
        "@os_command",
        "@string",
        "fuzzdb/attack/os-cmd-execution/shell-operators.txt",
        "fuzzdb/attack/os-cmd-execution/shell-delimiters.txt"
    ],
    "Auth.username": [
        "@auth_user",
        "@string",
        "fuzzdb/wordlists-user-passwd/unix-os/db-user-list.txt",
        "fuzzdb/wordlists-user-passwd/names/namelist.txt"
    ],
    "Auth.password": [
        "@auth_pass",
        "@string",
        "fuzzdb/wordlists-user-passwd/passwds/john.txt",
        "fuzzdb/wordlists-user-passwd/passwds/phpbb.txt"
    ],
    "Auth.hash": [
        "@string",
        "fuzzdb/attack/authentication/php_magic_hashes.fuzz.txt"
    ],
    "Debug.param": [
        "@string",
        "fuzzdb/attack/business-logic/CommonDebugParamNames.txt",
        "fuzzdb/attack/business-logic/DebugParams.Json.fuzz.txt"
    ],
    "Method.name": [
        "@string",
        "fuzzdb/attack/business-logic/CommonMethodNames.txt"
    ],
    "SSI.directive": [
        "@string",
        "fuzzdb/attack/server-side-include/server-side-includes-generic.txt"
    ],
    "Format.string": [
        "@string",
        "fuzzdb/attack/format-strings/format-strings.txt"
    ],
    "Integer.value": [
        "@numeric",
        "fuzzdb/attack/integer-overflow/integer-overflows.txt",
        "fuzzdb/wordlists-misc/numeric.txt"
    ],
    "Unicode.text": [
        "@unicode",
        "@string",
        "fuzzdb/attack/unicode/naughty-unicode.txt",
        "fuzzdb/attack/unicode/specialchars.txt",
        "fuzzdb/attack/unicode/emoji.txt",
        "fuzzdb/attack/unicode/right-to-left.txt",
        "fuzzdb/attack/unicode/corrupted.txt"
    ],
    "MIME.type": [
        "@string",
        "fuzzdb/attack/mimetypes/MimeTypes.txt"
    ],
    "LFI.path": [
        "@traversal",
        "@string",
        "fuzzdb/attack/lfi/JHADDIX_LFI.txt",
        "fuzzdb/attack/lfi/common-unix-httpd-log-locations.txt",
        "fuzzdb/attack/lfi/common-ms-httpd-log-locations.txt"
    ],
    "RFI.url": [
        "@traversal",
        "@string",
        "fuzzdb/attack/rfi/rfi.txt"
    ],
    "Redirect.url": [
        "@string",
        "fuzzdb/attack/redirect/redirect-urls-template.txt"
    ],
    "Directory.path": [
        "@string",
        "fuzzdb/attack/os-dir-indexing/directory-indexing.txt",
        "fuzzdb/attack/disclosure-directory/directory-indexing-generic.txt"
    ],
    "HTTP.header": [
        "@protocol",
        "@string",
        "fuzzdb/attack/http-protocol/http-request-header-field-names.txt",
        "fuzzdb/attack/http-protocol/http-response-header-field-names.txt",
        "fuzzdb/attack/http-protocol/crlf-injection.txt"
    ],
    "HTTP.cache": [
        "@string",
        "fuzzdb/attack/http-protocol/http-header-cache-poison.txt"
    ],
    "HTTP.parameter": [
        "@string",
        "@sql_injection",
        "fuzzdb/attack/http-protocol/hpp.txt"
    ],
    "HTTP.uri": [
        "@string",
        "@traversal",
        "fuzzdb/attack/http-protocol/known-uri-types.txt"
    ],
    "payload": [
        "@payload",
        "fuzzdb/attack/all-attacks/all-attacks-unix.txt",
        "fuzzdb/attack/all-attacks/all-attacks-xplatform.txt",
        "fuzzdb/attack/all-attacks/all-attacks-win.txt",
        "fuzzdb/attack/control-chars/terminal-escape-codes.txt"
    ],
    "string": [
        "@string",
        "fuzzdb/attack/unicode/naughty-unicode.txt",
        "fuzzdb/attack/unicode/specialchars.txt",
        "fuzzdb/attack/control-chars/NullByteRepresentations.txt",
        "fuzzdb/wordlists-misc/wordlist-alphanumeric-case.txt"
    ],
    "numeric": [
        "@numeric",
        "fuzzdb/wordlists-misc/numeric.txt",
        "fuzzdb/attack/integer-overflow/integer-overflows.txt"
    ],
    "DNS.subdomain": [
        "@string",
        "fuzzdb/discovery/dns/dnsmapCommonSubdomains.txt",
        "fuzzdb/discovery/dns/alexaTop1mAXFRcommonSubdomains.txt"
    ],
    "DNS.tld": [
        "@string",
        "fuzzdb/discovery/dns/gTLD.txt",
        "fuzzdb/discovery/dns/CcTLD.txt"
    ],
    "HTTP.useragent": [
        "@useragent",
        "@string",
        "fuzzdb/discovery/UserAgent/UserAgentListCommon.txt",
        "fuzzdb/discovery/UserAgent/UserAgents.txt"
    ],
    "HTTP.method": [
        "@protocol",
        "fuzzdb/discovery/common-methods/common-methods.txt"
    ],
    "WebSocket.subprotocol": [
        "@string",
        "fuzzdb/discovery/WebSocket/WebSocket-subprotocols.txt"
    ],
    "URI.scheme": [
        "@string",
        "fuzzdb/discovery/URI_SCHEMES/IANA_registerd_URI_schemes.txt"
    ],
    "SNMP.community": [
        "@string",
        "fuzzdb/wordlists-misc/wordlist-common-snmp-community-strings.txt"
    ],
    "Network.port": [
        "@numeric",
        "fuzzdb/wordlists-misc/common-http-ports.txt"
    ],
    "Session.id": [
        "@string",
        "fuzzdb/regex/sessionid.txt"
    ],
    "AWS.data": [
        "@string",
        "fuzzdb/regex/amazon.txt"
    ],
    "System.errors": [
        "@string",
        "fuzzdb/regex/errors.txt"
    ],
    "Data.pii": [
        "@string",
        "fuzzdb/regex/nsa-wordlist.txt"
    ],
}

# =============================
# Override logic: if override is True, only use the specified mapping, else combine all matches
FIELD_ADVANCED_DICTIONARIES = {

}


# Protocol-specific default values (expanded for comprehensive coverage)
FIELD_DEFAULT_VALUES = {
    # TCP Common Values
    "TCP.dport": [
        # Well-known ports
        21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995,
        # Common web ports
        8080, 8443, 8000, 8888, 3000, 5000, 9000, 9443,
        # Database ports
        1433, 3306, 5432, 1521, 27017, 6379,
        # Other services
        135, 139, 445, 587, 636, 993, 995, 1723, 3389,
        # High ports
        49152, 65535
    ],
    "TCP.sport": [1024, 2048, 4096, 8192, 16384, 32768, 49152, 65535],
    "TCP.flags": [
        0x02,  # SYN
        0x10,  # ACK
        0x18,  # PSH+ACK
        0x04,  # RST
        0x01,  # FIN
        0x08,  # PSH
        0x20,  # URG
        0x00,  # NULL
        0x3F,  # All flags
        0x29,  # Christmas tree (FIN+URG+PSH)
    ],
    "TCP.seq": [0, 1, 0xFFFFFFFF, 0x12345678, 0xDEADBEEF],
    "TCP.ack": [0, 1, 0xFFFFFFFF, 0x12345678, 0xDEADBEEF],
    "TCP.window": [0, 1, 65535, 32768, 8192, 1024],
    
    # UDP Common Values
    "UDP.dport": [
        # DNS and DHCP
        53, 67, 68,
        # Network services
        69, 123, 161, 162, 514, 5353,
        # VoIP and streaming
        5060, 5061, 1935, 554,
        # Gaming and other
        27015, 7777, 25565,
        # High numbers
        49152, 65535
    ],
    "UDP.sport": [1024, 2048, 4096, 8192, 16384, 32768, 49152, 65535],
    "UDP.len": [8, 16, 32, 64, 128, 256, 512, 1024, 1472, 65535],
    
    # IP Common Values
    "IP.version": [4, 6, 0, 15],  # IPv4, IPv6, invalid values
    "IP.ihl": [5, 15, 0, 1],  # Standard, max, invalid values
    "IP.ttl": [0, 1, 32, 64, 128, 255],
    "IP.tos": [0, 1, 2, 4, 8, 16, 32, 64, 128, 255],
    "IP.frag": [0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 8191],
    "IP.id": [0, 1, 0x1234, 0x5678, 0xFFFF],
    "IP.proto": [
        1,   # ICMP
        6,   # TCP
        17,  # UDP
        41,  # IPv6
        47,  # GRE
        50,  # ESP
        51,  # AH
        255, # Reserved
        0    # Invalid
    ],
    
    # ICMP Common Values
    "ICMP.type": [
        0,   # Echo Reply
        3,   # Destination Unreachable
        4,   # Source Quench
        5,   # Redirect
        8,   # Echo Request
        9,   # Router Advertisement
        10,  # Router Solicitation
        11,  # Time Exceeded
        12,  # Parameter Problem
        13,  # Timestamp Request
        14,  # Timestamp Reply
        15,  # Information Request
        16,  # Information Reply
        17,  # Address Mask Request
        18,  # Address Mask Reply
        255  # Invalid
    ],
    "ICMP.code": [0, 1, 2, 3, 4, 5, 15, 255],
    "ICMP.id": [0, 1, 0x1234, 0x5678, 0xFFFF],
    "ICMP.seq": [0, 1, 0x1234, 0x5678, 0xFFFF],
    
    # DNS Common Values
    "DNS.id": [0x0000, 0x1234, 0x5678, 0x9abc, 0xdef0, 0xffff],
    "DNS.qr": [0, 1],  # Query/Response
    "DNS.opcode": [0, 1, 2, 4, 5, 15],  # Standard, Inverse, Status, Notify, Update, Reserved
    "DNS.aa": [0, 1],  # Authoritative Answer
    "DNS.tc": [0, 1],  # Truncated
    "DNS.rd": [0, 1],  # Recursion Desired
    "DNS.ra": [0, 1],  # Recursion Available
    "DNS.rcode": [0, 1, 2, 3, 4, 5, 6, 15],  # Response codes
    "DNSQR.qtype": [
        1,    # A
        2,    # NS
        5,    # CNAME
        6,    # SOA
        12,   # PTR
        15,   # MX
        16,   # TXT
        28,   # AAAA
        33,   # SRV
        255,  # ANY
        65535 # Invalid
    ],
    "DNSQR.qclass": [1, 3, 4, 255, 65535],  # IN, CH, HS, ANY, Invalid
    
    # Ethernet Common Values
    "Ether.type": [
        0x0800,  # IPv4
        0x0806,  # ARP
        0x86dd,  # IPv6
        0x8100,  # VLAN
        0x88cc,  # LLDP
        0x0000,  # Invalid
        0xFFFF   # Invalid
    ],
    
    # ARP Common Values
    "ARP.hwtype": [1, 6, 7, 15, 16, 17, 18, 19, 20],  # Ethernet, IEEE 802, etc.
    "ARP.ptype": [0x0800, 0x86dd, 0x0000, 0xFFFF],  # IPv4, IPv6, Invalid
    "ARP.hwlen": [6, 8, 16, 20, 0, 255],  # MAC length variants
    "ARP.plen": [4, 16, 0, 255],  # IP address length variants
    "ARP.op": [1, 2, 3, 4, 8, 9, 10, 11, 65535],  # REQUEST, REPLY, RREQUEST, RREPLY, etc.
    
    # IPv6 Common Values (for future extension)
    "IPv6.version": [6, 4, 0, 15],
    "IPv6.tc": [0, 1, 2, 4, 8, 16, 32, 64, 128, 255],
    "IPv6.fl": [0, 1, 0x12345, 0xFFFFF],
    "IPv6.plen": [0, 40, 60, 1500, 65535],
    "IPv6.nh": [6, 17, 1, 41, 43, 44, 58, 59, 60, 255],  # TCP, UDP, ICMP, IPv6, etc.
    "IPv6.hlim": [1, 64, 128, 255],
    
    # Common Payload Sizes
    "payload_sizes": [0, 1, 8, 16, 32, 64, 128, 256, 512, 1024, 1500, 9000, 65535],
    
    # Common String Lengths for fuzzing
    "string_lengths": [0, 1, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 65535],
    
    # LDAP Common Values
    "LDAP.filter": ["(objectClass=*)", "(cn=*)", "(uid=admin)", "(&(cn=*)(mail=*))", "(|(cn=admin)(uid=admin))"],
    "LDAP.dn": ["cn=admin,dc=example,dc=com", "uid=test,ou=users,dc=domain,dc=com", "dc=com", "ou=users"],
    
    # JSON Common Values
    "JSON.data": ['{"test": "value"}', '{"admin": true}', '{"id": 1}', '{"null": null}', '{"array": []}'],
    
    # XML Common Values
    "XML.data": ["<root></root>", "<test>value</test>", "<?xml version='1.0'?>", "<![CDATA[data]]>"],
    
    # XPath Common Values
    "XPath.query": ["//user", "//*[@id='admin']", "//password", "count(//user)", "string-length(//password)"],
    
    # NoSQL Common Values
    "NoSQL.query": ['{"$ne": null}', '{"$gt": ""}', '{"$regex": ".*"}', '{"$where": "1==1"}'],
    
    # File Upload Common Values
    "File.extension": [".php", ".asp", ".jsp", ".js", ".html", ".txt", ".exe", ".bat", ".sh"],
    "File.name": ["test.txt", "../../etc/passwd", "null.txt", "con.txt", "aux.txt", "prn.txt"],
    
    # HTML/JavaScript Common Values
    "HTML.attribute": ["id", "class", "src", "href", "onclick", "onload", "style", "data-*"],
    "HTML.tag": ["script", "img", "iframe", "object", "embed", "form", "input", "div"],
    "JS.event": ["onclick", "onload", "onmouseover", "onerror", "onfocus", "onblur"],
    
    # OS Command Values
    "OS.command": ["id", "whoami", "ls", "dir", "cat /etc/passwd", "type c:\\windows\\system32\\drivers\\etc\\hosts"],
    
    # Authentication Common Values
    "Auth.username": ["admin", "administrator", "root", "test", "guest", "user", "sa", "postgres"],
    "Auth.password": ["password", "admin", "123456", "password123", "root", "test", "guest"],
    
    # Debug Parameters
    "Debug.param": ["debug", "test", "dev", "trace", "verbose", "log", "show_errors"],
    
    # Format String Values
    "Format.string": ["%s", "%x", "%n", "%08x", "AAAA%08x.%08x", "%s%s%s%s%s"],
    
    # Integer Overflow Values
    "Integer.value": [0, -1, 2147483647, -2147483648, 4294967295, 65535, 32767, -32768],
    
    # Unicode Values
    "Unicode.text": ["test", "тест", "测试", "テスト", "🚀", "﷽", "\u202e", "\ufeff"],
    
    # MIME Types
    "MIME.type": ["text/html", "application/json", "image/jpeg", "application/octet-stream", "text/xml"],
    
    # Network Discovery Values
    "DNS.subdomain": ["www", "mail", "ftp", "admin", "test", "dev", "api", "secure", "login"],
    "DNS.tld": [".com", ".org", ".net", ".edu", ".gov", ".mil", ".int", ".co.uk"],
    "HTTP.useragent": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    ],
    "HTTP.method": ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "TRACE", "CONNECT"],
    "WebSocket.subprotocol": ["chat", "echo", "binary", "text", "json"],
    "URI.scheme": ["http", "https", "ftp", "file", "data", "ldap", "tel", "mailto"],
    
    # SNMP Values
    "SNMP.community": ["public", "private", "admin", "manager", "agent", "read", "write"],
    "Network.port": [80, 443, 21, 22, 23, 25, 53, 110, 143, 993, 995],
    
    # Session and Data Pattern Values
    "Session.id": ["SESSIONID123", "sess_abc123", "token_xyz789", "auth_key456"],
    "AWS.data": ["AKIAIOSFODNN7EXAMPLE", "aws-access-key", "s3-bucket-name", "ec2-instance"],
    "System.errors": ["404 Not Found", "500 Internal Server Error", "Access Denied", "Permission Error"],
}

# =============================
# Weight Mappings (Type, Name, Advanced)
# =============================
"""
Weight Mappings for Scapy LibFuzzer
- FIELD_TYPE_WEIGHTS: weights by field type
- FIELD_NAME_WEIGHTS: weights by field name
- FIELD_ADVANCED_WEIGHTS: advanced/conditional weight logic

All weights are floats (0.0-1.0) representing fuzzing priority:
- 0.0-0.2: Critical protocol fields (version, type, length fields)  
- 0.2-0.4: Important but less critical fields (ports, addresses)
- 0.4-0.7: Application fields with moderate impact
- 0.7-0.9: High-value fuzzing targets (payloads, user data)
- 0.9-1.0: Maximum priority fields (application payloads, attack vectors)

Philosophy: Lower weights for fields that break basic packet functionality,
higher weights for application-layer fields where vulnerabilities are common.
"""

FIELD_TYPE_WEIGHTS = {
    "string": 0.6,
    "numeric": 0.4,
    "payload": 0.9,
    "address": 0.7,
    "protocol": 0.8,
    "email": 0.75,
    "useragent": 0.6,
    "auth_user": 0.8,
    "auth_pass": 0.8,
    "file_name": 0.7,
    "file_ext": 0.75,
    "dns_name": 0.7,
    "xpath": 0.85,
    "ldap": 0.85,
    "json": 0.8,
    "xml": 0.8,
    "os_command": 0.95,
    "sql_injection": 0.9,
    "xss": 0.9,
    "unicode": 0.6,
    "traversal": 0.85,
    "shell": 0.9,
}

FIELD_NAME_WEIGHTS = {
    # Critical protocol fields - lower weights to maintain functionality
    "TCP.dport": 0.3,      # Destination port critical for delivery - reduced from 0.9
    "UDP.dport": 0.3,      # UDP destination port - reduced from 0.9  
    "IP.dst": 0.25,        # Destination IP critical for routing - reduced from 0.8
    "TCP.flags": 0.15,     # TCP flags control connection state - reduced from 0.75
    "Ether.type": 0.1,     # Ethernet type determines packet parsing - reduced from 0.4
    "IP.version": 0.05,    # IP version critical for basic parsing - reduced from 0.2
    "IPv6.nh": 0.15,       # IPv6 next header critical - will be added below
    
    # Application layer fields - higher weights for fuzzing effectiveness
    "Raw.load": 0.95,      # Payload fuzzing is most valuable
    "DNSQR.qname": 0.9,    # DNS queries are good fuzz targets
    "HTTPRequest.Path": 0.9,
    "HTTPRequest.Method": 0.85,
    
    # Semi-critical fields - moderate weights
    "UDP.sport": 0.4,      # Source ports less critical - increased from 0.5
    "TCP.sport": 0.4,      # Source ports less critical - adding for consistency
    "IP.src": 0.3,         # Source IP less critical - reduced from 0.45  
    "TCP.window": 0.3,     # Window size can affect performance - reduced from 0.4
    
    # Protocol overhead fields - low to moderate weights
    "IP.tos": 0.2,         # Type of service - reduced from 0.4
    "IP.frag": 0.2,        # Fragmentation flags - reduced from 0.45
    "IP.ihl": 0.05,         # IP header length critical - reduced from 0.25
    "IP.id": 0.1,           # IP identification field - critical for fragmentation
    "IP.ttl": 0.15,         # IP time-to-live - critical for routing
    "IP.options": 0.05,     # IP options - rarely used, but can break parsing
    "TCP.urgptr": 0.1,      # TCP urgent pointer - critical for some flows
    "TCP.reserved": 0.05,   # TCP reserved bits - must be valid for parsing
    "TCP.options": 0.05,    # TCP options - rarely used, but can break parsing
    "ICMP.type": 0.1,       # ICMP type - critical for protocol parsing
    "ICMP.code": 0.1,       # ICMP code - critical for protocol parsing
    "ICMP.id": 0.1,         # ICMP identifier - critical for echo/request flows
    "ICMP.seq": 0.1,        # ICMP sequence - critical for echo/request flows

    # MAC layer fields - very low weights
    "Ether.dst": 0.15,     # MAC addresses less critical in most scenarios - reduced
    "Ether.src": 0.1,      # Source MAC least important - reduced from 0.25
    "ARP.hwsrc": 0.2,      # ARP hardware addresses - reduced from 0.3
    "ARP.hwdst": 0.2,      # ARP hardware addresses - reduced from 0.3
    "ARP.psrc": 0.25,      # ARP protocol addresses - reduced from 0.35
    "ARP.pdst": 0.25,      # ARP protocol addresses - reduced from 0.35
    
    # Application protocol fields - good targets for fuzzing
    "HTTPRequest.User-Agent": 0.7,
    "HTTPRequest.Host": 0.75,
    "HTTPRequest.Http-Version": 0.3,
    "SMTP.mailfrom": 0.8,
    "SMTP.rcptto": 0.8,
    "payload": 0.9,
    "string": 0.6,
    "numeric": 0.4,
    
    # IPv6 fields - critical protocol fields should have lower weights
    "IPv6.tc": 0.3,        # Traffic class - reduced from 0.4
    "IPv6.fl": 0.2,        # Flow label - reduced from 0.3  
    "IPv6.plen": 0.15,     # Payload length critical - reduced from 0.5
    "IPv6.nh": 0.15,       # Next header critical for parsing - reduced from 0.6
    "IPv6.hlim": 0.3,      # Hop limit similar to TTL - reduced from 0.5
    
    # Additional critical protocol fields that should have low weights
    "IP.len": 0.1,         # IP total length field critical for parsing
    "IP.proto": 0.15,      # IP protocol field critical for next layer parsing
    "IP.chksum": 0.05,     # IP checksum critical for packet validation
    "TCP.seq": 0.2,        # TCP sequence numbers affect connection state
    "TCP.ack": 0.2,        # TCP acknowledgment numbers affect connection state  
    "TCP.dataofs": 0.1,    # TCP data offset critical for parsing
    "TCP.chksum": 0.05,    # TCP checksum critical for packet validation
    "UDP.len": 0.1,        # UDP length field critical for parsing
    "UDP.chksum": 0.05,    # UDP checksum critical for packet validation
    "ICMP.chksum": 0.05,   # ICMP checksum critical for packet validation
    "DNS.ancount": 0.1,    # DNS answer count affects parsing
    "DNS.nscount": 0.1,    # DNS authority count affects parsing  
    "DNS.arcount": 0.1,    # DNS additional count affects parsing
    "LDAP.filter": 0.85,
    "LDAP.dn": 0.75,
    "JSON.data": 0.8,
    "XML.data": 0.8,
    "XPath.query": 0.85,
    "NoSQL.query": 0.85,
    "OS.command": 0.95,
    "OS.shell": 0.9,
    "File.name": 0.8,
    "File.extension": 0.75,
    "File.path": 0.85,
    "LFI.path": 0.9,
    "RFI.url": 0.9,
    "HTML.attribute": 0.7,
    "HTML.tag": 0.75,
    "JS.event": 0.8,
    "JS.code": 0.85,
    "HTTP.header": 0.65,
    "HTTP.cache": 0.6,
    "HTTP.parameter": 0.7,
    "HTTP.uri": 0.6,
    "Auth.username": 0.8,
    "Auth.password": 0.8,
    "Auth.hash": 0.75,
    "SSI.directive": 0.8,
    "Format.string": 0.85,
    "Integer.value": 0.6,
    "Redirect.url": 0.7,
    "Unicode.text": 0.6,
    "MIME.type": 0.5,
    "Debug.param": 0.7,
    "Method.name": 0.6,
    "Directory.path": 0.65,
    "DNS.subdomain": 0.75,
    "DNS.tld": 0.5,
    "HTTP.useragent": 0.6,
    "HTTP.method": 0.8,
    "WebSocket.subprotocol": 0.7,
}

FIELD_ADVANCED_WEIGHTS = [
    # Example: match by name, type, and length, with mode
    {
        "match": {"name": "Raw.load", "type": "string", "length": ">1024"},
        "weight": 0.99,
        "mode": "override"
    },
    # Example: match by type and context
    {
        "match": {"type": "string", "context": "html"},
        "weight": 0.8,
        "mode": "min"
    },
    # ...add more as needed
]

# =============================
# Layer-based weight scaling
# =============================
# Scale field fuzzing weights based on how deep the layer is within the packet.
# Lower scaling factors reduce fuzzing of outer layers more aggressively.
# For a layer with K layers below it, the effective weight multiplier is
# (LAYER_WEIGHT_SCALING ** K). 
# Examples:
#   - 0.9: Mild reduction (10% reduction per layer depth)
#   - 0.5: Moderate reduction (50% reduction per layer depth)  
#   - 0.1: Aggressive reduction (90% reduction per layer depth)
# Innermost layer (depth=0) is never scaled (multiplier=1.0)
LAYER_WEIGHT_SCALING: float = 0.9


