Name:           freeipa-python
Version:        0.2.0
Release:        3%{?dist}
Summary:        FreeIPA authentication server

Group:          System Environment/Base
License:        GPL
URL:            http://www.freeipa.org
Source0:        %{name}-%{version}.tgz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch: 	noarch

Requires: python

%{!?python_sitelib: %define python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}

%define pkgpythondir  %{python_sitelib}/ipa
%define configdir /etc/ipa

%description
FreeIPA is a server for identity, policy, and audit.

%prep
%setup -q

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{pkgpythondir}
mkdir -p %{buildroot}%{configdir}

make install DESTDIR=%{buildroot}


%clean
rm -rf %{buildroot}


%files
%defattr(-,root,root,-)
%{pkgpythondir}/*
%config(noreplace) %{configdir}/ipa.conf


%changelog
* Mon Aug  5 2007 Rob Crittenden <rcritten@redhat.com> - 0.1.0-3
- Abstracted client class to work directly or over RPC

* Wed Aug  1 2007 Rob Crittenden <rcritten@redhat.com> - 0.1.0-2
- Add User class
- Add kerberos authentication to the XML-RPC request made from tools.

* Fri Jul 27 2007 Karl MacMillan <kmacmill@localhost.localdomain> - 0.1.0-1
- Initial rpm version


