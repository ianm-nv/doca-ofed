Name:           multiperf
Summary:        IB Performance tests
Version:        3.0
Release:        3.0
License:        BSD 3-Clause, GPL v2 or later
Group:          Productivity/Networking/Diagnostic
Source:         %{name}-%{version}.tar.gz
Url:            ""
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
BuildRequires:  libibverbs-devel

%description
gen3 uverbs microbenchmarks

%prep
%setup -q

%build
%configure
%{__make}

%install
rm -rf $RPM_BUILD_ROOT
make DESTDIR=%{buildroot} install

%clean
rm -rf ${RPM_BUILD_ROOT}

%files
%defattr(-, root, root)
%doc README COPYING
%_bindir/*

%changelog
* Sun Feb 08 2015 - gilr@mellanox.com
- Initial Package, Version 3.0
