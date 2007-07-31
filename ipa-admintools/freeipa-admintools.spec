Name:           freeipa-admintools
Version:        0.1.0
Release:        1%{?dist}
Summary:        FreeIPA authentication server

Group:          System Environment/Base
License:        GPL
URL:            http://www.freeipa.org
Source0:        %{name}-%{version}.tgz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch: 	noarch

Requires: python freeipa-python

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
%{_sbindir}/ipa-adduser
%{_sbindir}/ipa-finduser


%changelog
* Fri Jul 27 2007 Karl MacMillan <kmacmill@localhost.localdomain> - 0.1.0-1
- Initial rpm version


