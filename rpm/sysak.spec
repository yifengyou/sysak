Name: sysak
Summary: system analyse kit
Version: 1.0.0
Release: 1%{?dist}
License: GPLv3+

%description
system analyse kit
commit: 

%build
echo source_dir=%{source_dir}
if [ %{source_dir} ]; then
	echo linux_version=%{linux_version}
	for version in %{linux_version}; do
		make -C %{source_dir} KERNEL_VERSION=$version clean_middle
		make -C %{source_dir} KERNEL_VERSION=$version
	done
fi

%install
mkdir -p $RPM_BUILD_ROOT/usr/local/sbin
/bin/cp -rf /home/weipu.zy/develop/sysAK_wetp/out/.sysak_compoents $RPM_BUILD_ROOT/usr/local/sbin/.sysak_compoents
/bin/cp -rf /home/weipu.zy/develop/sysAK_wetp/out/sysak $RPM_BUILD_ROOT/usr/local/sbin/

%preun

/sbin/lsmod | grep sysak > /dev/null
if [ 0 -eq 0 ]; then
	/sbin/rmmod sysak
	exit 0
fi

%files
/usr/local/sbin/.sysak_compoents
/usr/local/sbin/sysak

%changelog
