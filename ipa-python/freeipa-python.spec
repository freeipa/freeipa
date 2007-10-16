%define pyver  %(%{__python} -c 'import sys ; print sys.version[:3]')
%define pynext %(%{__python} -c 'print %{pyver} + 0.1')

Name:           freeipa-python
Version:        0.4.0
Release:        1%{?dist}
Summary:        FreeIPA authentication server

Group:          System Environment/Base
License:        GPL
URL:            http://www.freeipa.org
Source0:        http://www.freeipa.org/downloads/%{name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch: 	noarch
BuildRequires: python >= 0:%{pyver}, python < 0:%{pynext}
Requires: python >= 0:%{pyver}, python < 0:%{pynext}
Requires: PyKerberos

%description
FreeIPA is a server for identity, policy, and audit.

%prep
%setup -q

%build
%{__python} setup.py build

%install
rm -rf %{buildroot}
%{__python} setup.py install -O1 --root=%{buildroot} --record=INSTALLED_FILES
sed 's|^\(.*\.pyo\)$|%ghost \1|' < INSTALLED_FILES > %{name}-%{version}.files
find $RPM_BUILD_ROOT%{_libdir}/python%{pyver}/site-packages/* -type d \
  | sed "s|^$RPM_BUILD_ROOT|%dir |" >> %{name}-%{version}.files

%clean
rm -rf %{buildroot}

%files -f %{name}-%{version}.files
%defattr(-,root,root,-)
%config(noreplace) %{_sysconfdir}/ipa.conf


%changelog
* Fri Aug 17 2007 Karl MacMillan <kmacmill@redhat.com> = 0.2.0-4
- Added PyKerberos dep.

* Mon Aug  5 2007 Rob Crittenden <rcritten@redhat.com> - 0.1.0-3
- Abstracted client class to work directly or over RPC

* Wed Aug  1 2007 Rob Crittenden <rcritten@redhat.com> - 0.1.0-2
- Add User class
- Add kerberos authentication to the XML-RPC request made from tools.

* Fri Jul 27 2007 Karl MacMillan <kmacmill@localhost.localdomain> - 0.1.0-1
- Initial rpm version


