Name:           ipa-radius-server
Version:        0.99.0
Release:        1%{?dist}
Summary:        IPA authentication server - radius plugin

Group:          System Environment/Base
License:        GPLv2
URL:            http://www.freeipa.org
Source0:        %{name}-%{version}.tgz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch: 	noarch

Requires: python
Requires: ipa-server
Requires: freeradius

%description
Radius plugin for an IPA server

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
%{_sbindir}/ipa*

%dir %{_usr}/share/ipa/plugins
%{_usr}/share/ipa/plugins/*

%dir %{_usr}/share/ipa/ipaserver/plugins
%{_usr}/share/ipa/ipaserver/plugins/*

%changelog
* Thu Feb 21 2008 Rob Crittenden <rcritten@redhat.com> - 0.99.0-1
- Version bump for release

* Thu Jan 31 2008 Rob Crittenden <rcritten@redhat.com> - 0.6.0-3
- Marked with wrong license. IPA is GPLv2.

* Thu Jan 17 2008 Rob Crittenden <rcritten@redhat.com> - 0.6.0-2
- Fixed License in specfile

* Fri Dec 21 2007 Karl MacMillan <kmacmill@redhat.com> - 0.6.0-1
- Version bump for release

* Wed Dec 12 2007 Karl MacMillan <kmacmill@redhat.com> - 0.5.0-1
- Initial version
