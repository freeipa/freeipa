import six
from ipalib import _
if six.PY3:
    unicode = str

# Both constants can be used as masks against trust direction
# because bi-directional has two lower bits set.
TRUST_ONEWAY = 1
TRUST_BIDIRECTIONAL = 3

# Trust join behavior
# External trust -- allow creating trust to a non-root domain in the forest
TRUST_JOIN_EXTERNAL = 1

# We don't want to import any of Samba Python code here just for constants
# Since these constants set in MS-ADTS, we can rely on their stability
LSA_TRUST_ATTRIBUTE_NON_TRANSITIVE = 0x00000001

_trust_direction_dict = {
        1: _('Trusting forest'),
        2: _('Trusted forest'),
        3: _('Two-way trust')
}

_trust_status_dict = {
        True: _('Established and verified'),
        False: _('Waiting for confirmation by remote side')
}

_trust_type_dict_unknown = _('Unknown')

# Trust type is a combination of ipanttrusttype and ipanttrustattributes
# We shift trust attributes by 3 bits to left so bit 0 becomes bit 3 and
# 2+(1 << 3) becomes 10.
_trust_type_dict = {
        1: _('Non-Active Directory domain'),
        2: _('Active Directory domain'),
        3: _('RFC4120-compliant Kerberos realm'),
        10: _('Non-transitive external trust to a domain in '
              'another Active Directory forest'),
        11: _('Non-transitive external trust to an RFC4120-'
              'compliant Kerberos realm')
}


def trust_type_string(level, attrs):
    """
    Returns a string representing a type of the trust.
    The original field is an enum:
      LSA_TRUST_TYPE_DOWNLEVEL  = 0x00000001,
      LSA_TRUST_TYPE_UPLEVEL    = 0x00000002,
      LSA_TRUST_TYPE_MIT        = 0x00000003
    """
    transitive = int(attrs) & LSA_TRUST_ATTRIBUTE_NON_TRANSITIVE
    string = _trust_type_dict.get(int(level) | (transitive << 3),
                                  _trust_type_dict_unknown)
    return unicode(string)


def trust_direction_string(level):
    """
    Returns a string representing a direction of the trust.
    The original field is a bitmask taking two bits in use
      LSA_TRUST_DIRECTION_INBOUND  = 0x00000001,
      LSA_TRUST_DIRECTION_OUTBOUND = 0x00000002
    """
    string = _trust_direction_dict.get(int(level), _trust_type_dict_unknown)
    return unicode(string)


def trust_status_string(level):
    string = _trust_status_dict.get(level, _trust_type_dict_unknown)
    return unicode(string)
