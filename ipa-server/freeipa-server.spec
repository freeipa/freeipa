Name:           freeipa-server
Version:        0.1.0
Release:        3%{?dist}
Summary:        FreeIPA authentication server

Group:          System Environment/Base
License:        GPL
URL:            http://www.freeipa.org
Source0:        %{name}-%{version}.tgz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch: 	noarch

Requires: python fedora-ds-base krb5-server krb5-server-ldap nss-tools openldap-clients httpd mod_python mod_auth_kerb python-ldap freeipa-python cyrus-sasl-gssapi

%description
FreeIPA is a server for identity, policy, and audit.

%prep
%setup -q

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_sbindir}

make install DESTDIR=%{buildroot}


%clean
rm -rf %{buildroot}


%files
%defattr(-,root,root,-)
%{_sbindir}/ipa-server-install
%{_sbindir}/ipa-server-setupssl

%dir %{_usr}/share/ipa
%{_usr}/share/ipa/*


%changelog
* Mon Aug  5 2007 Rob Crittenden <rcritten@redhat.com> - 0.1.0-3
- Abstracted client class to work directly or over RPC

* Wed Aug  1 2007 Rob Crittenden <rcritten@redhat.com> - 0.1.0-2
- Add mod_auth_kerb and cyrus-sasl-gssapi to Requires
- Remove references to admin server in ipa-server-setupssl
- Generate a client certificate for the XML-RPC server to connect to LDAP with
- Create a keytab for Apache
- Create an ldif with a test user
- Provide a certmap.conf for doing SSL client authentication

* Fri Jul 27 2007 Karl MacMillan <kmacmill@localhost.localdomain> - 0.1.0-1
- Initial rpm version


