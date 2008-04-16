Name:           ipa-client
Version:        1.0.0
Release:        1%{?dist}
Summary:        IPA client Setup script for RHEL-4

Group:          System Environment/Base
License:        GPLv2
URL:            http://www.freeipa.org
Source0:        %{name}-%{version}.tgz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:      noarch
#BuildRequires:  python-devel

Requires: python
Requires: python-ldap

%{!?python_sitelib: %define python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}

%description
IPA is a server for identity, policy, and audit.
The client package provide install and configuration scripts for RHEL-4 clients.

%prep
%setup -q
%configure --prefix=/usr

%build

make

%install
rm -rf %{buildroot}
%{__python} setup.py install --no-compile --root=%{buildroot}
%makeinstall \
	SBINDIR=$RPM_BUILD_ROOT%{_sbindir}
mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/ipa
install -m644 ipa.conf $RPM_BUILD_ROOT%{_sysconfdir}/ipa/ipa.conf

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_sbindir}/ipa-client-setup
%{python_sitelib}/ipachangeconf.py*
%config(noreplace) %{_sysconfdir}/ipa/ipa.conf

%changelog
* Thu Apr  3 2008 Rob Crittenden <rcritten@redhat.com> - 1.0.0-1
- Version bump for release

* Mon Mar 25 2008 Simo Sorce <ssorce@redhat.com> - 0.99.0-1
- First RHEL-4 release

