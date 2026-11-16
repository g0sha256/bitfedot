Name:           bitfedot
Version:        0.2.0
Release:        1%{?dist}
Summary:        A complete, private, hardened Bitcoin node for Fedora
License:        Unlicense
URL:            https://github.com/G0SHA256/bitfedot
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch
# Built and tested for Fedora 45 and newer

BuildRequires:  python3-devel
BuildRequires:  desktop-file-utils
BuildRequires:  libappstream-glib
Requires:       python3-gobject
Requires:       gobject-introspection
Requires:       gtk4
Requires:       libadwaita
Requires:       curl
Requires:       gnupg2
Requires:       podman
Requires:       tor
Requires:       polkit
Requires:       firewalld
Requires:       nftables
Requires:       iproute
Recommends:     flatpak
Recommends:     gnome-shell-extension-appindicator

%description
BitFedot installs and manages Bitcoin Core, Fulcrum, Mempool and Tor from a
native GTK interface. Upstream releases are verified against pinned signing
keys, and everything runs as unprivileged systemd user services.

%prep
%autosetup

%generate_buildrequires
%pyproject_buildrequires

%build
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files bitfedot
install -Dm644 bitfedot/data/io.github.g0sha256.BitFedot.desktop \
    %{buildroot}%{_datadir}/applications/io.github.g0sha256.BitFedot.desktop
install -Dm644 bitfedot/data/io.github.g0sha256.BitFedot.metainfo.xml \
    %{buildroot}%{_metainfodir}/io.github.g0sha256.BitFedot.metainfo.xml
install -Dm644 bitfedot/data/icons/hicolor/scalable/apps/io.github.g0sha256.BitFedot.svg \
    %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/io.github.g0sha256.BitFedot.svg
install -Dm644 bitfedot/data/icons/hicolor/symbolic/apps/io.github.g0sha256.BitFedot-symbolic.svg \
    %{buildroot}%{_datadir}/icons/hicolor/symbolic/apps/io.github.g0sha256.BitFedot-symbolic.svg

%check
desktop-file-validate %{buildroot}%{_datadir}/applications/*.desktop
appstream-util validate-relax --nonet %{buildroot}%{_metainfodir}/*.metainfo.xml
%{python3} -m unittest discover tests

%files -f %{pyproject_files}
%license LICENSE
%doc README.md CHANGELOG.md SECURITY.md THANKS.md AGENTS.md docs/RELEASING.md
%{_bindir}/bitfedot
%{_datadir}/applications/io.github.g0sha256.BitFedot.desktop
%{_metainfodir}/io.github.g0sha256.BitFedot.metainfo.xml
%{_datadir}/icons/hicolor/*/apps/io.github.g0sha256.BitFedot*.svg

%changelog
* Mon Nov 16 2026 BitFedot contributors - 0.1.0-1
- Initial public release
