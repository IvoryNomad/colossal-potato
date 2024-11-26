# Copyright (c) 2024 Nathan Eric Norman
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
    name: dns_lookup
    author: Nathan Eric Norman
    version_added: "2.14"
    short_description: Query any DNS record type
    description:
        - This lookup plugin allows querying all DNS record types supported by dnspython
        - Supports A, AAAA, AFSDB, APL, CAA, CDNSKEY, CDS, CERT, CNAME, CSYNC,
          DHCID, DLV, DNAME, DNSKEY, DS, EUI48, EUI64, GPOS, HINFO, HIP, IPSECKEY,  
          KEY, KX, LOC, MX, NAPTR, NS, NSAP, NSAP-PTR, NSEC, NSEC3, NSEC3PARAM,
          OPENPGPKEY, PTR, RP, RRSIG, RT, SIG, SMIMEA, SOA, SPF, SRV, SSHFP,
          TA, TKEY, TLSA, TSIG, TXT, URI, and others
        - Returns structured data with all fields for each record type
    options:
        _terms:
            description: Domain names to look up
            required: True
        record_type:
            description: Type of DNS record to query
            type: str
            default: 'A'
        nameserver:
            description: Custom nameserver to query 
            type: str
            default: None
        timeout:
            description: DNS query timeout in seconds
            type: float
            default: 2.0
"""

EXAMPLES = r"""
- name: Query any record type
  debug:
    msg: "{{ lookup('dns_lookup', 'example.com', record_type='A') }}"

- name: TLSA record lookup
  debug:
    msg: "{{ lookup('dns_lookup', '_443._tcp.example.com', record_type='TLSA') }}"

- name: SSHFP record lookup
  debug:
    msg: "{{ lookup('dns_lookup', 'example.com', record_type='SSHFP') }}"

- name: CAA record lookup
  debug:
    msg: "{{ lookup('dns_lookup', 'example.com', record_type='CAA') }}"
"""

RETURN = r"""
_raw:
    description:
        - List of DNS records found
        - Returns structured data with all fields for each record type
    type: list
    elements: dict
"""

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display
import inspect

try:
    import dns.resolver
    import dns.exception
    import dns.rdatatype
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

display = Display()

class LookupModule(LookupBase):

    def format_txt_record(self, rdata):
        """Format TXT-like record data, handling byte strings and concatenated strings"""
        if hasattr(rdata, 'strings'):
            return [s.decode('utf-8') if isinstance(s, bytes) else str(s) 
                   for s in rdata.strings]
        return [str(rdata)]

    def get_rdata_fields(self, rdata):
        """Extract all available fields from an rdata object"""
        fields = {}
        
        # Get all public attributes that aren't methods or internal fields
        for name, value in inspect.getmembers(rdata):
            if (not name.startswith('_') and 
                not inspect.ismethod(value) and 
                not inspect.isfunction(value)):
                
                # Handle bytes and special types
                if isinstance(value, bytes):
                    fields[name] = value.decode('utf-8', errors='replace')
                elif hasattr(value, '__str__'):
                    fields[name] = str(value)
                else:
                    fields[name] = value

        return fields

    def format_rdata(self, rdata, record_type):
        """Format any rdata object into a structured dict"""
        result = self.get_rdata_fields(rdata)
        
        # Special handling for common record types
        if record_type in ('A', 'AAAA'):
            result['address'] = str(rdata)

        elif record_type in ('CNAME', 'PTR', 'NS'):
            result['target'] = str(rdata)

        elif record_type == 'SOA':
            result.update({
                'mname': str(rdata.mname),
                'rname': str(rdata.rname),
                'serial': rdata.serial,
                'refresh': rdata.refresh,
                'retry': rdata.retry,
                'expire': rdata.expire,
                'minimum': rdata.minimum
            })

        elif record_type == 'MX':
            result.update({
                'preference': rdata.preference,
                'exchange': str(rdata.exchange)
            })

        elif record_type == 'SRV':
            result.update({
                'priority': rdata.priority,
                'weight': rdata.weight,
                'port': rdata.port,
                'target': str(rdata.target)
            })

        elif record_type == 'NAPTR':
            result.update({
                'order': rdata.order,
                'preference': rdata.preference,
                'flags': rdata.flags.decode() if isinstance(rdata.flags, bytes) else str(rdata.flags),
                'service': rdata.service.decode() if isinstance(rdata.service, bytes) else str(rdata.service),
                'regexp': rdata.regexp.decode() if isinstance(rdata.regexp, bytes) else str(rdata.regexp),
                'replacement': str(rdata.replacement)
            })

        elif record_type == 'TLSA':
            result.update({
                'usage': rdata.usage,
                'selector': rdata.selector,
                'mtype': rdata.mtype,
                'cert': rdata.cert.hex()
            })

        elif record_type == 'CAA':
            result.update({
                'flags': rdata.flags,
                'tag': rdata.tag.decode() if isinstance(rdata.tag, bytes) else str(rdata.tag),
                'value': rdata.value.decode() if isinstance(rdata.value, bytes) else str(rdata.value)
            })

        elif record_type == 'SSHFP':
            result.update({
                'algorithm': rdata.algorithm,
                'fp_type': rdata.fp_type,
                'fingerprint': rdata.fingerprint.hex()
            })

        elif record_type == 'TXT':
            result['strings'] = self.format_txt_record(rdata)

        elif record_type == 'URI':
            result.update({
                'priority': rdata.priority,
                'weight': rdata.weight,
                'target': str(rdata.target)
            })

        # Add string representation for all record types
        result['string'] = str(rdata)
        
        return result

    def run(self, terms, variables=None, **kwargs):
        if not HAS_DNS:
            raise AnsibleError('python-dnspython package is required for dns_lookup')

        self.set_options(var_options=variables, direct=kwargs)
        
        # Get options
        record_type = kwargs.get('record_type', 'A').upper()
        nameserver = kwargs.get('nameserver', None)
        timeout = float(kwargs.get('timeout', 2.0))

        # Validate record type
        try:
            rdatatype = dns.rdatatype.from_text(record_type)
        except dns.rdatatype.UnknownRdatatype:
            raise AnsibleError(f"Unknown DNS record type: {record_type}")

        ret = []
        resolver = dns.resolver.Resolver()
        
        if nameserver:
            resolver.nameservers = [nameserver]
        resolver.timeout = timeout

        for term in terms:
            display.debug(f"DNS lookup for {term} (type: {record_type})")
            
            try:
                answers = resolver.resolve(term, record_type)
                for rdata in answers:
                    formatted = self.format_rdata(rdata, record_type)
                    ret.append(formatted)

            except dns.resolver.NXDOMAIN:
                display.debug(f"No {record_type} record found for {term}")
                continue
            except dns.exception.DNSException as e:
                raise AnsibleError(f"DNS lookup failed for {term}: {str(e)}")

        return ret
