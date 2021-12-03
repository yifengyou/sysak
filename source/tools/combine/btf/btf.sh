TOOLS_ROOT=`dirname "$0"`
zip_path=${TOOLS_ROOT}/BTF/btf.7z
btf_dir=${TOOLS_ROOT}/BTF
btf_path=${TOOLS_ROOT}/BTF/vmlinux-`uname -r`
if [ ! -f "$btf_path" ]; then
${TOOLS_ROOT}/BTF/7za e ${zip_path} -o${btf_dir} vmlinux-btf/vmlinux-`uname -r`
fi