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

Requires: python fedora-ds-base krb5-server krb5-server-ldap

%{!?python_sitelib: %define python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}

%define pkgpythondir  %{python_sitelib}/%{name}

%description
Madison is a set of tools and libraries for SELinux policy generation.

%prep
%setup -q

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%{_sbindir}/ipa-server-install
%{_sbindir}/ipa-server-setupssl

%dir %{_usr}/share/ipa
%{_usr}/share/ipa/*


%changelog
* Fri Jul 27 2007 Karl MacMillan <kmacmill@localhost.localdomain> - 0.1.0-1
- Initial rpm version


