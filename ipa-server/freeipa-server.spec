Name:           freeipa-server
Version:        0.1.0
Release:        1%{?dist}
Summary:        FreeIPA authentication server

Group:          System Environment/Base
License:        GPL
URL:            http://www.freeipa.org
Source0:        %{name}-%{version}.tgz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch: 	noarch

Requires: python fedora-ds-base krb5-server krb5-server-ldap nss-tools openldap-clients httpd mod_python

%define httpd_conf /etc/httpd/conf.d

%description
FreeIPA is a server for identity, policy, and audit.

%prep
%setup -q

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_sbindir}
mkdir -p %{buildroot}%{httpd_conf}

make install DESTDIR=%{buildroot}


%clean
rm -rf %{buildroot}


%files
%defattr(-,root,root,-)
%{_sbindir}/ipa-server-install
%{_sbindir}/ipa-server-setupssl

%dir %{_usr}/share/ipa
%{_usr}/share/ipa/*

%{httpd_conf}/ipa.conf


%changelog
* Fri Jul 27 2007 Karl MacMillan <kmacmill@localhost.localdomain> - 0.1.0-1
- Initial rpm version


