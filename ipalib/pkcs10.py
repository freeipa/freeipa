# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2009  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

# Read PKCS#10 certificate requests (see RFC 2986 and 5280)

# NOTE: Not every extension is currently handled. Known to now work:
#  2.5.29.37 - extKeyUsage

import sys, string, base64
from pyasn1.type import base,tag,namedtype,namedval,univ,constraint,char,useful
from pyasn1.codec.der import decoder, encoder
from pyasn1 import error
import copy

# Common OIDs found in a subject
oidtable = { "2.5.4.3":  "CN",
             "2.5.4.6":  "C",
             "2.5.4.7":  "L",
             "2.5.4.8":  "ST",
             "2.5.4.10": "O",
             "2.5.4.11": "OU",
             "1.2.840.113549.1.9.1": "E",
             "0.9.2342.19200300.100.1.25": "DC",
           }

# Some useful OIDs
FRIENDLYNAME = '1.2.840.113549.1.9.20'
EXTENSIONREQUEST = '1.2.840.113549.1.9.14'

MAX = 32 # from mozilla/security/nss/lib/util/secasn1t.h

class DirectoryString(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('teletexString', char.TeletexString().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType('printableString', char.PrintableString().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType('universalString', char.UniversalString().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType('utf8String', char.UTF8String().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType('bmpString', char.BMPString().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        )

class AttributeValue(DirectoryString): pass

class AttributeType(univ.ObjectIdentifier): pass

class AttributeTypeAndValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
       namedtype.NamedType('type', AttributeType()),
       namedtype.NamedType('value', AttributeValue()) # FIXME, could be any type
        )

class KeyPurposeId(univ.ObjectIdentifier): pass

class ExtKeyUsageSyntax(univ.SequenceOf):
    componentType = KeyPurposeId()

class UPN(char.UTF8String):
    tagSet = char.UTF8String.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
        )

class AttributeValueSet(univ.SetOf):
    componentType = univ.Any()
    sizeSpec = univ.SetOf.sizeSpec + constraint.ValueSizeConstraint(1, MAX)

class Attribute(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', AttributeType()),
        namedtype.NamedType('values', AttributeValueSet()),
        )

class Attributes(univ.SetOf):
    componentType = Attribute()

class RelativeDistinguishedName(univ.SetOf):
    componentType = AttributeTypeAndValue()

class RDNSequence(univ.SequenceOf):
    componentType = RelativeDistinguishedName()

class Name(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('', RDNSequence())
        )

    def get_components(self):
        components = self.getComponentByPosition(0)
        complist = []
        for idx in range(len(components)):
            attrandvalue = components[idx].getComponentByPosition(0)
            oid = attrandvalue.getComponentByPosition(0)
            # FIXME, should handle any string type
            value = attrandvalue.getComponentByPosition(1).getComponentByType(char.PrintableString.tagSet)
            if value is None:
                value = attrandvalue.getComponentByPosition(1).getComponentByType(char.UTF8String.tagSet)
                if value is None:
                    value = attrandvalue.getComponentByPosition(1).getComponentByType(char.IA5String.tagSet)
            vout = value.prettyOut(value).decode('utf-8')
            oidout = oid.prettyOut(oid).decode('utf-8')
            c = ((oidtable.get(oidout, oidout), vout))
            complist.append(c)

        return tuple(complist)

class AnotherName(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type-id', univ.ObjectIdentifier()),
        namedtype.NamedType('value', univ.Any())
    )

class rfc822Name(char.IA5String):
    tagSet = char.IA5String.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        )

class dNSName(char.IA5String):
    tagSet = char.IA5String.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
        )

class x400Address(univ.OctetString):
    tagSet = univ.OctetString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 3)
        )

class directoryName(Name):
    tagSet = Name.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 4)
        )

class uniformResourceIdentifier(char.IA5String):
    tagSet = char.IA5String.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6)
        )

# Not all general types are handled, nor are these necessarily done
# per the specification.
class GeneralName(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('otherName', AnotherName().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('rfc822Name', rfc822Name()), #1
        namedtype.NamedType('dNSName', dNSName()), #2
        namedtype.NamedType('x400Address', x400Address()), #3
        namedtype.NamedType('directoryName', directoryName()), #4
        # 5 FIXME
        namedtype.NamedType('uniformResourceIdentifier', uniformResourceIdentifier()), #6
#        namedtype.NamedType('uniformResourceIdentifier', char.IA5String(tagSet=char.IA5String.tagSet.tagImplicitly(tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 6)))),
    )

class GeneralNames(univ.SequenceOf):
    componentType = GeneralName()
    sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(1, MAX)

class SubjectAltName(univ.SequenceOf):
    componentType = GeneralName()
    sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(1, MAX)

class DistributionPointName(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('fullName', GeneralNames().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('nameRelativeToCRLIssuer', RelativeDistinguishedName().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
    )

class DistributionPoint(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('distributionPoint', DistributionPointName().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType('reasons', univ.BitString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))), # FIXME
        namedtype.OptionalNamedType('cRLIssuer', GeneralNames().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
        )

class cRLDistributionPoints(univ.SequenceOf):
    componentType = DistributionPoint()
    sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(1, MAX)

class basicConstraints(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('cA', univ.Boolean('False')),
        namedtype.OptionalNamedType('pathLenConstraint', univ.Integer()),
    )

class AlgorithmIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType('parameters', univ.Any())
        )

class SubjectPublicKeyInfo(univ.Sequence):
     componentType = namedtype.NamedTypes(
         namedtype.NamedType('algorithm', AlgorithmIdentifier()),
         namedtype.NamedType('subjectPublicKey', univ.BitString())
         )

class Version(univ.Integer): pass

class CertificationRequestInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', Version()),
        namedtype.NamedType('subject', Name()),
        namedtype.NamedType('subjectPublicKeyInfo', SubjectPublicKeyInfo()),
        namedtype.OptionalNamedType('attributes', Attributes().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)))
        )

class CertificationRequest(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('certificationRequestInfo', CertificationRequestInfo()),
        namedtype.NamedType('signatureAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('signatureValue', univ.BitString())
        )

    def get_version(self):
        info = self.getComponentByName('certificationRequestInfo')
        version = info.getComponentByName('version')
        return version._value

    def get_subject(self):
        info = self.getComponentByName('certificationRequestInfo')
        return info.getComponentByName('subject')

    def get_subjectaltname(self):
        attrs = self.get_attributes()
        attrdict = dict(attrs)
        if EXTENSIONREQUEST in attrdict:
            # Extensions are a 3 position tuple
            for ext in attrdict[EXTENSIONREQUEST]:
                if ext[0] == '2.5.29.17':
                    # alt name is in the dNSName position
                    return ext[2][2]

    def get_attributes(self):
        info = self.getComponentByName('certificationRequestInfo')
        attrs =  info.getComponentByName('attributes')
        attributes = []

        for idx in range(len(attrs)):
            atype = attrs[idx].getComponentByPosition(0)
            aval = attrs[idx].getComponentByPosition(1)

            # The attribute list is of type Any, need to re-encode
            aenc = encoder.encode(aval, maxChunkSize=1024)
            decoded = decoder.decode(aenc)[0]
            oid = atype.prettyOut(atype)

            if oid == "1.2.840.113549.1.9.20": # PKCS#9 Friendly Name
                value = decoded.getComponentByPosition(0)
                t = (oid, value.prettyOut(value).decode('utf-8'))
                attributes.append(t)
            elif oid == "1.2.840.113549.1.9.14": # PKCS#9 Extension Req
                extensions = []
                extlist = decoded.getComponentByPosition(0)
                for jdx in range(len(extlist)):
                    ext = extlist.getComponentByPosition(jdx)
                    # An extension has 3 elements:
                    # oid
                    # bool - critical
                    # value
                    if len(ext) == 2: # If no critical, default to False
                        extoid = atype.prettyOut(ext.getComponentByPosition(0))
                        critical = False
                        extvalue = ext.getComponentByPosition(1)
                    else:
                        extoid = atype.prettyOut(ext.getComponentByPosition(0))
                        critical = bool(ext.getComponentByPosition(1)._value)
                        extvalue = ext.getComponentByPosition(2)

                    if extoid == '2.5.29.19': # basicConstraints
                        extdecoded = decoder.decode(extvalue._value, asn1Spec=basicConstraints())[0]
                        ca = bool(extdecoded[0])
                        if len(extdecoded) == 2: # path length is optional
                            pathlen = extdecoded[1]._value
                        else:
                            pathlen = None
                        constraint = (ca, pathlen)
                        e = (extoid, critical, constraint)
                        extensions.append(e)
                        continue
                    elif extoid == '2.5.29.31': # cRLDistributionPoints
                        extdecoded = decoder.decode(extvalue._value, asn1Spec=cRLDistributionPoints())[0]
                        distpoints = []
                        for elem in range(len(extdecoded)):
                            name = extdecoded[elem]
                            # DistributionPoint is position 0
                            distpoint = name.getComponentByPosition(0)
                            # fullName is position 0
                            fullname = distpoint.getComponentByPosition(0)
                            for crl in range(len(fullname)):
                                # Get the GeneralName, URI type
                                uri = fullname.getComponentByPosition(crl).getComponentByPosition(5)
                                distpoints.append(uri.prettyOut(uri).decode('utf-8'))
                        e = (extoid, critical, tuple(distpoints))
                        extensions.append(e)
                        continue

                    # The data is is encoded as "Any". Pull the raw data out
                    # and re-decode it using a different specification.
                    try:
                        extdecoded = decoder.decode(extvalue._value, asn1Spec=GeneralNames())[0]
                    except error.PyAsn1Error:
                        # I've seen CSRs where this isn't a sequence of names
                        # but is a single name, try to handle that too.
                        try:
                            extdecoded = decoder.decode(extvalue._value, asn1Spec=GeneralName())[0]
                            extdecoded = [extdecoded]
                        except error.PyAsn1Error, e:
                            # skip for now
                            generalnames = 9*["Error"]
                            e = (extoid, critical, tuple(generalnames))
                            extensions.append(e)
                            continue

                    # We now have a list of extensions in the order they
                    # are in the request as GeneralNames. We iterate through
                    # each of those to get a GeneralName. We then have to
                    # iterate through that to find the position set in it.

                    # Note that not every type will be returned. Those that
                    # are handled are returned in a tuple in the position
                    # which they are in the request.
                    generalnames = 9*[None]
                    for elem in range(len(extdecoded)):
                        name = extdecoded[elem]
                        for n in range(len(name)):
                            if name[n] is None:
                                continue
                            if generalnames[n] is None:
                                generalnames[n] = []
                            if n == 3: # OctetString
                                generalnames[n].append(name[n]._value)
                            if n in [1, 2, 6]: # IA5String
                                if n == 6 and extoid == "2.5.29.37":
                                    # Extended key usage
                                    v = copy.deepcopy(extvalue._value)
                                    othername = decoder.decode(v, asn1Spec=ExtKeyUsageSyntax())[0]
                                    keyusage = []
                                    for l in range(len(othername)):
                                        keyusage.append(othername[l].prettyOut(othername[l]))

                                    generalnames[n] = tuple(keyusage)
                                else:
                                    generalnames[n].append(name[n].prettyOut(name[n]).decode('utf-8'))
                            if n == 0: # AnotherName
                                nameoid = name[n].getComponentByPosition(0)
                                nameoid = nameoid.prettyOut(nameoid)
                                val = name[n].getComponentByPosition(1)
                                if nameoid == "1.3.6.1.4.1.311.20.2.3": # UPN
                                    v = copy.deepcopy(val._value)
                                    othername = decoder.decode(v, asn1Spec=UPN())[0]
                                    generalnames[0].append(othername.prettyOut(othername).decode('utf-8'))

                    e = (extoid, critical, tuple(generalnames))
                    extensions.append(e)
                t = (oid, tuple(extensions))
                attributes.append(t)

        return tuple(attributes)

def strip_header(csr):
    """
    Remove the header and footer from a CSR.
    """
    headerlen = 40
    s = csr.find("-----BEGIN NEW CERTIFICATE REQUEST-----")
    if s == -1:
        headerlen = 36
        s = csr.find("-----BEGIN CERTIFICATE REQUEST-----")
    if s >= 0:
        e = csr.find("-----END")
        csr = csr[s+headerlen:e]

    return csr

def load_certificate_request(csr):
    """
    Given a base64-encoded certificate request, with or without the
    header/footer, return a request object.
    """
    csr = strip_header(csr)

    substrate = base64.b64decode(csr)

    return decoder.decode(substrate, asn1Spec=CertificationRequest())[0]

if __name__ == '__main__':
    # Read PEM certs from stdin and print them out in plain text

    stSpam, stHam, stDump = 0, 1, 2
    state = stSpam

    for certLine in sys.stdin.readlines():
        certLine = string.strip(certLine)
        if state == stSpam:
            if state == stSpam:
                if certLine == '-----BEGIN NEW CERTIFICATE REQUEST-----':
                    certLines = []
                    state = stHam
                    continue
        if state == stHam:
            if certLine == '-----END NEW CERTIFICATE REQUEST-----':
                state = stDump
            else:
                certLines.append(certLine)
        complist = []
        if state == stDump:
            substrate = ''
            for certLine in certLines:
                substrate = substrate + base64.b64decode(certLine)

            request = decoder.decode(substrate, asn1Spec=CertificationRequest())[0]
            subject = request.get_subject()
            attrs = request.get_attributes()
            print "Attributes:"
            print attrs

            print "Subject:"
            complist = subject.get_components()
            print complist
            out=""
            for c in complist:
                out = out + "%s=%s," % (c[0], c[1])
            print out[:-1]

            print request.get_subjectaltname()

            # Re-encode the request just to be sure things are working
            assert encoder.encode(request, maxChunkSize=1024) == substrate, 'cert recode fails'

            state = stSpam
