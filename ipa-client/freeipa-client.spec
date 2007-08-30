Name:           freeipa-client
Version:        0.1.0
Release:        2%{?dist}
Summary:        FreeIPA client

Group:          System Environment/Base
License:        GPL
URL:            http://www.freeipa.org
Source0:        %{name}-%{version}.tgz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Requires: python python-ldap python-krbV freeipa-python

%description
FreeIPA is a server for identity, policy, and audit.
The client package provide install and configuration scripts for clients.

%prep
%setup -q

%build

make DESTDIR=%{buildroot}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_sbindir}

make install DESTDIR=%{buildroot}


%clean
rm -rf %{buildroot}


%files
%defattr(-,root,root,-)
%{_sbindir}/ipa-client-install

%dir %{_usr}/share/ipa
%{_usr}/share/ipa/*

%changelog
* Thu Aug 16 2007 Simo Sorce <ssorce@redhat.com> - 0.1.0-1
- Initial rpm version


