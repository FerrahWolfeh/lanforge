%{!?cargo_target_dir: %global cargo_target_dir target}

Name:           lanforge
Version:        0.25.0
Release:        1%{?dist}
Summary:        Unified IPv4/IPv6 Network Control Daemon and Router Orchestrator

License:        MPL-2.0
URL:            https://github.com/FerrahWolfeh/lanforge
Source0:        %{name}-%{version}.tar.gz
Source1:        lanforge.service
Source2:        lanforge.sysusers
Source3:        lanforge.tmpfiles
Source4:        lanforge.toml

BuildRequires:  rust >= 1.83
BuildRequires:  cargo
BuildRequires:  gcc
BuildRequires:  systemd-rpm-macros

Requires:       systemd
Requires:       nftables
Requires:       iproute

%description
Lanforge is a complete, modern, high-performance router and local network
orchestrator written in Rust. It integrates DHCPv4, DHCPv6, IPv6 Router
Advertisement (SLAAC), DNS forwarding with adblock filtering, TFTP, Wake-on-LAN,
PPPoE client with eBPF/XDP offload, nftables firewall automation, and an
administrative CLI and WebUI.

%prep
%if %{undefined _build_in_place}
%autosetup -n %{name}-%{version}
%endif

%build
if [ ! -f "%{cargo_target_dir}/release/lanforged" ] || [ ! -f "%{cargo_target_dir}/release/lanforge" ]; then
    cargo build --release --locked --bin lanforged --bin lanforge --bin lanforge-lab
fi

%install
# Binaries
install -D -p -m 0755 %{cargo_target_dir}/release/lanforged %{buildroot}%{_bindir}/lanforged
install -D -p -m 0755 %{cargo_target_dir}/release/lanforge %{buildroot}%{_bindir}/lanforge
install -D -p -m 0755 %{cargo_target_dir}/release/lanforge-lab %{buildroot}%{_bindir}/lanforge-lab

# Systemd service
install -D -p -m 0644 %{SOURCE1} %{buildroot}%{_unitdir}/lanforge.service

# Sysusers and Tmpfiles
install -D -p -m 0644 %{SOURCE2} %{buildroot}%{_sysusersdir}/lanforge.conf
install -D -p -m 0644 %{SOURCE3} %{buildroot}%{_tmpfilesdir}/lanforge.conf

# Configuration file
install -D -p -m 0640 %{SOURCE4} %{buildroot}%{_sysconfdir}/lanforge/lanforge.toml

# State directories
install -d -m 0750 %{buildroot}%{_sharedstatedir}/lanforge
install -d -m 0750 %{buildroot}/run/lanforge

%pre
%sysusers_create_package lanforge %{SOURCE2}

%post
%systemd_post lanforge.service
%tmpfiles_create %{_tmpfilesdir}/lanforge.conf

%preun
%systemd_preun lanforge.service

%postun
%systemd_postun_with_restart lanforge.service

%files
%license LICENSE 2>/dev/null || :
%{_bindir}/lanforged
%{_bindir}/lanforge
%{_bindir}/lanforge-lab
%{_unitdir}/lanforge.service
%{_sysusersdir}/lanforge.conf
%{_tmpfilesdir}/lanforge.conf
%dir %attr(0755, root, lanforge) %{_sysconfdir}/lanforge
%config(noreplace) %attr(0640, root, lanforge) %{_sysconfdir}/lanforge/lanforge.toml
%dir %attr(0750, root, lanforge) %{_sharedstatedir}/lanforge
%ghost %dir %attr(0750, root, lanforge) /run/lanforge

%changelog
* Mon Sep 07 2026 Ferrah Aiko <ferrahwolfeh@proton.me> - 0.25.0-1
- Initial packaging for Fedora Server with dnf5 support
- Systemd hardening, capability bounding, and group-based unprivileged CLI administration
