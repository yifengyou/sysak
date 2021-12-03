#!/bin/bash
# author: Shuyi Cheng
# email: chengshuyi@linux.alibaba.com

TOOLS_ROOT=$(dirname "$0")
zip_path=${TOOLS_ROOT}/BTF/btf.7z
btf_dir=${TOOLS_ROOT}/BTF
btf_path=${btf_dir}/vmlinux-$(uname -r)

usage() {
    echo "sysak btf: Extract the btf file to the specified directory"
    echo "options: -h, help information"
    echo "         -d, Specify the path, default directory path: ${btf_dir}"
}

extract_btf() {
    ${TOOLS_ROOT}/BTF/7za e ${zip_path} -o${btf_dir} vmlinux-btf/vmlinux-$(uname -r)
}

while getopts 'd:h' OPT; do
    case $OPT in
    "h")
        usage
        exit 0
        ;;
    "d")
        btf_dir=$OPTARG
        btf_path=${btf_dir}/vmlinux-$(uname -r)
        ;;
    *)
        usage
        exit -1
        ;;
    esac
done

if [ ! -f "$btf_path" ]; then
    extract_btf
fi
