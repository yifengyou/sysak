#!/bin/bash
# author: Shuyi Cheng
# email: chengshuyi@linux.alibaba.com

zip_path=${SYSAK_WORK_PATH}/tools/BTF/btf.7z
btf_dir=${SYSAK_WORK_PATH}/tools
btf_path=${btf_dir}/vmlinux-$(uname -r)

usage() {
    echo "sysak btf: Extract the btf file to the specified directory"
    echo "options: -h, help information"
    echo "         -d, Specify the path, default directory path: ${btf_dir}"
}

extract_btf() {
    ${SYSAK_WORK_PATH}/tools/BTF/7za e ${zip_path} -o${btf_dir} vmlinux-btf/vmlinux-$(uname -r)
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
