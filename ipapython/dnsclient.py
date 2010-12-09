#
# Copyright 2001, 2005 Red Hat, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import struct
import socket
import sys

import acutil

DNS_C_IN = 1
DNS_C_CS = 2
DNS_C_CHAOS = 3
DNS_C_HS = 4
DNS_C_ANY = 255

DNS_T_A = 1
DNS_T_NS = 2
DNS_T_CNAME = 5
DNS_T_SOA = 6
DNS_T_NULL = 10
DNS_T_WKS = 11
DNS_T_PTR = 12
DNS_T_HINFO = 13
DNS_T_MX = 15
DNS_T_TXT = 16
DNS_T_AAAA = 28
DNS_T_SRV = 33
DNS_T_ANY = 255

DEBUG_DNSCLIENT = False

class DNSQueryHeader:
	FORMAT = "!HBBHHHH"
	def __init__(self):
		self.dns_id = 0
		self.dns_rd = 0
		self.dns_tc = 0
		self.dns_aa = 0
		self.dns_opcode = 0
		self.dns_qr = 0
		self.dns_rcode = 0
		self.dns_z = 0
		self.dns_ra = 0
		self.dns_qdcount = 0
		self.dns_ancount = 0
		self.dns_nscount = 0
		self.dns_arcount = 0

	def pack(self):
		return struct.pack(DNSQueryHeader.FORMAT,
			self.dns_id,
			(self.dns_rd & 1) |
			(self.dns_tc & 1) << 1 |
			(self.dns_aa & 1) << 2 |
			(self.dns_opcode & 15) << 3 |
			(self.dns_qr & 1) << 7,
			(self.dns_rcode & 15) |
			(self.dns_z & 7) << 4 |
			(self.dns_ra & 1) << 7,
			self.dns_qdcount,
			self.dns_ancount,
			self.dns_nscount,
			self.dns_arcount)

	def unpack(self, data):
		(self.dns_id, byte1, byte2, self.dns_qdcount, self.dns_ancount,
			self.dns_nscount, self.dns_arcount) = struct.unpack(DNSQueryHeader.FORMAT, data[0:self.size()])
		self.dns_rd = byte1 & 1
		self.dns_tc = (byte1 >> 1) & 1
		self.dns_aa = (byte1 >> 2) & 1
		self.dns_opcode = (byte1 >> 3) & 15
		self.dns_qr = (byte1 >> 7) & 1
		self.dns_rcode = byte2 & 15
		self.dns_z = (byte2 >> 4) & 7
		self.dns_ra = (byte1 >> 7) & 1
	
	def size(self):
		return struct.calcsize(DNSQueryHeader.FORMAT)

def unpackQueryHeader(data):
	header = DNSQueryHeader()
	header.unpack(data)
	return header

class DNSResult:
	FORMAT = "!HHIH"
	QFORMAT = "!HH"
	def __init__(self):
		self.dns_name = ""
		self.dns_type = 0
		self.dns_class = 0
		self.dns_ttl = 0
		self.dns_rlength = 0
		self.rdata = None

	def unpack(self, data):
		(self.dns_type, self.dns_class, self.dns_ttl,
			self.dns_rlength) = struct.unpack(DNSResult.FORMAT, data[0:self.size()])
			
	def qunpack(self, data):
		(self.dns_type, self.dns_class) = struct.unpack(DNSResult.QFORMAT, data[0:self.qsize()])

	def size(self):
		return struct.calcsize(DNSResult.FORMAT)

	def qsize(self):
		return struct.calcsize(DNSResult.QFORMAT)

class DNSRData:
	def __init__(self):
		pass	

#typedef struct dns_rr_a {
#	u_int32_t address;
#} dns_rr_a_t;
#
#typedef struct dns_rr_aaaa {
#       unsigned char address[16];
#} dns_rr_aaaa_t;
#
#typedef struct dns_rr_cname {
#	const char *cname;
#} dns_rr_cname_t;
#
#typedef struct dns_rr_hinfo {
#	const char *cpu, *os;
#} dns_rr_hinfo_t;
#
#typedef struct dns_rr_mx {
#	u_int16_t preference;
#	const char *exchange;
#} dns_rr_mx_t;
#
#typedef struct dns_rr_null {
#	unsigned const char *data;
#} dns_rr_null_t;
#
#typedef struct dns_rr_ns {
#	const char *nsdname;
#} dns_rr_ns_t;
#
#typedef struct dns_rr_ptr {
#	const char *ptrdname;
#} dns_rr_ptr_t;
#
#typedef struct dns_rr_soa {
#	const char *mname;
#	const char *rname;
#	u_int32_t serial;
#	int32_t refresh;
#	int32_t retry;
#	int32_t expire;
#	int32_t minimum;
#} dns_rr_soa_t;
#
#typedef struct dns_rr_txt {
#	const char *data;
#} dns_rr_txt_t;
#
#typedef struct dns_rr_srv {
#	const char *server;
#	u_int16_t priority;
#	u_int16_t weight;
#	u_int16_t port;
#} dns_rr_srv_t;

def dnsNameToLabel(name):
	out = ""
	name = name.split(".")
	for part in name:
		out += chr(len(part)) + part
	return out

def dnsFormatQuery(query, qclass, qtype):
	header = DNSQueryHeader()

	header.dns_id = 0 # FIXME: id = 0
	header.dns_rd = 1 # don't know why the original code didn't request recursion for non SOA requests
	header.dns_qr = 0 # query
	header.dns_opcode = 0 # standard query
	header.dns_qdcount = 1 # single query

	qlabel = dnsNameToLabel(query)
	if not qlabel:
		return ""

	out = header.pack() + qlabel
	out += chr(qtype >> 8)
	out += chr(qtype & 0xff)
	out += chr(qclass >> 8)
	out += chr(qclass & 0xff)

	return out

def dnsParseLabel(label, base):
	# returns (output, rest)
	if not label:
		return ("", None)

	update = 1
	rest = label
	output = ""
	skip = 0
	
	try:
		while ord(rest[0]):
			if ord(rest[0]) & 0xc0:
				rest = base[((ord(rest[0]) & 0x3f) << 8) + ord(rest[1]):]
				if update:
					skip += 2
				update = 0
				continue
			output += rest[1:ord(rest[0]) + 1] + "."
			if update:
				skip += ord(rest[0]) + 1
			rest = rest[ord(rest[0]) + 1:]
	except IndexError:
		return ("", None)
	return (label[skip+update:], output)

def dnsParseA(data, base):
	rdata = DNSRData()
	if len(data) < 4:
		rdata.address = 0
		return None
		
	rdata.address = (ord(data[0])<<24) | (ord(data[1])<<16) | (ord(data[2])<<8) | (ord(data[3])<<0)
		
	if DEBUG_DNSCLIENT:
		print "A = %d.%d.%d.%d." % (ord(data[0]), ord(data[1]), ord(data[2]), ord(data[3]))
	return rdata

def dnsParseAAAA(data, base):
	rdata = DNSRData()
	if len(data) < 16:
		rdata.address = 0
		return None

        rdata.address = list(struct.unpack('!16B', data))
        if DEBUG_DNSCLIENT:
            print socket.inet_ntop(socket.AF_INET6,
                                   struct.pack('!16B', *rdata.address))
        return rdata

def dnsParseText(data):	
	if len(data) < 1:
		return ("", None)
	tlen = ord(data[0])
	if len(data) < tlen + 1:
		return ("", None)
	return (data[tlen+1:], data[1:tlen+1])

def dnsParseNS(data, base):
	rdata = DNSRData()
	(rest, rdata.nsdname) = dnsParseLabel(data, base)
	if DEBUG_DNSCLIENT:
		print "NS DNAME = \"%s\"." % (rdata.nsdname)
	return rdata

def dnsParseCNAME(data, base):
	rdata = DNSRData()
	(rest, rdata.cname) = dnsParseLabel(data, base)
	if DEBUG_DNSCLIENT:
		print "CNAME = \"%s\"." % (rdata.cname)
	return rdata

def dnsParseSOA(data, base):
	rdata = DNSRData()
	format = "!IIIII"
	
	(rest, rdata.mname) = dnsParseLabel(data, base)
	if rdata.mname is None:
		return None
	(rest, rdata.rname) = dnsParseLabel(rest, base)
	if rdata.rname is None:
		return None
	if len(rest) < struct.calcsize(format):
		return None

	(rdata.serial, rdata.refresh, rdata.retry, rdata.expire,
		rdata.minimum) = struct.unpack(format, rest[:struct.calcsize(format)])
	
	if DEBUG_DNSCLIENT:
		print "SOA(mname) = \"%s\"." % rdata.mname
		print "SOA(rname) = \"%s\"." % rdata.rname
		print "SOA(serial) = %d." % rdata.serial
		print "SOA(refresh) = %d." % rdata.refresh
		print "SOA(retry) = %d." % rdata.retry
		print "SOA(expire) = %d." % rdata.expire
		print "SOA(minimum) = %d." % rdata.minimum
	return rdata

def dnsParseNULL(data, base):
	# um, yeah
	return None

def dnsParseWKS(data, base):
	return None

def dnsParseHINFO(data, base):
	rdata = DNSRData()
	(rest, rdata.cpu) = dnsParseText(data)
	if rest:
		(rest, rdata.os) = dnsParseText(rest)
	if DEBUG_DNSCLIENT:
		print "HINFO(cpu) = \"%s\"." % rdata.cpu
		print "HINFO(os) = \"%s\"." % rdata.os
	return rdata

def dnsParseMX(data, base):
	rdata = DNSRData()
	if len(data) < 2:
		return None
	rdata.preference = (ord(data[0]) << 8) | ord(data[1])
	(rest, rdata.exchange) = dnsParseLabel(data[2:], base)
	if DEBUG_DNSCLIENT:
		print "MX(exchanger) = \"%s\"." % rdata.exchange
		print "MX(preference) = %d." % rdata.preference
	return rdata

def dnsParseTXT(data, base):
	rdata = DNSRData()
	(rest, rdata.data) = dnsParseText(data)
	if DEBUG_DNSCLIENT:
		print "TXT = \"%s\"." % rdata.data
	return rdata

def dnsParsePTR(data, base):
	rdata = DNSRData()
	(rest, rdata.ptrdname) = dnsParseLabel(data, base)
	if DEBUG_DNSCLIENT:
		print "PTR = \"%s\"." % rdata.ptrdname
        return rdata

def dnsParseSRV(data, base):
	rdata = DNSRData()
	format = "!HHH"
	flen = struct.calcsize(format)
	if len(data) < flen:
		return None
		
	(rdata.priority, rdata.weight, rdata.port) = struct.unpack(format, data[:flen])
	(rest, rdata.server) = dnsParseLabel(data[flen:], base)
	if DEBUG_DNSCLIENT:
		print "SRV(server) = \"%s\"." % rdata.server
		print "SRV(weight) = %d." % rdata.weight
		print "SRV(priority) = %d." % rdata.priority
		print "SRV(port) = %d." % rdata.port
	return rdata

def dnsParseResults(results):
	try:
		header = unpackQueryHeader(results)
	except struct.error:
		return []
	
	if header.dns_qr != 1: # should be a response
		return []

	if header.dns_rcode != 0: # should be no error
		return []

	rest = results[header.size():]
	
	rrlist = []

	for i in xrange(header.dns_qdcount):
		if not rest:
			return []
		
		qq = DNSResult()

		(rest, label) = dnsParseLabel(rest, results)
		if label is None:
			return []

		if len(rest) < qq.qsize():
			return []
		
		qq.qunpack(rest)
		
		rest = rest[qq.qsize():]

		if DEBUG_DNSCLIENT:
			print "Queried for '%s', class = %d, type = %d." % (label,
				qq.dns_class, qq.dns_type)

	for i in xrange(header.dns_ancount + header.dns_nscount + header.dns_arcount):
		(rest, label) = dnsParseLabel(rest, results)
		if label is None:
			return []

		rr = DNSResult()

		rr.dns_name = label

		if len(rest) < rr.size():
			return []

		rr.unpack(rest)
		
		rest = rest[rr.size():]

		if DEBUG_DNSCLIENT:
			print "Answer %d for '%s', class = %d, type = %d, ttl = %d." % (i,
				rr.dns_name, rr.dns_class, rr.dns_type,
				rr.dns_ttl)

		if len(rest) < rr.dns_rlength:
			if DEBUG_DNSCLIENT:
				print "Answer too short."
			return []
		
		fmap = { DNS_T_A: dnsParseA, DNS_T_NS: dnsParseNS,
			DNS_T_CNAME: dnsParseCNAME, DNS_T_SOA: dnsParseSOA,
			DNS_T_NULL: dnsParseNULL, DNS_T_WKS: dnsParseWKS,
			DNS_T_PTR: dnsParsePTR, DNS_T_HINFO: dnsParseHINFO,
			DNS_T_MX: dnsParseMX, DNS_T_TXT: dnsParseTXT,
			DNS_T_AAAA : dnsParseAAAA, DNS_T_SRV: dnsParseSRV}

		if not rr.dns_type in fmap:
			if DEBUG_DNSCLIENT:
				print "Don't know how to parse RR type %d!" %	rr.dns_type
		else:
			rr.rdata = fmap[rr.dns_type](rest[:rr.dns_rlength], results)

		rest = rest[rr.dns_rlength:]
		rrlist += [rr]

	return rrlist

def query(query, qclass, qtype):
	qdata = dnsFormatQuery(query, qclass, qtype)
	if not qdata:
		return []
	answer = acutil.res_send(qdata)
	if not answer:
		return []
	return dnsParseResults(answer)

if __name__ == '__main__':
	DEBUG_DNSCLIENT = True
	print "Sending query."
	rr = query(len(sys.argv) > 1 and sys.argv[1] or "devserv.devel.redhat.com.",
		DNS_C_IN, DNS_T_ANY)
	sys.exit(0)
