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
    echo "         -l, show vmlinux btf list"
}

extract_btf() {
    source_path=${SYSAK_WORK_PATH}/tools/vmlinux-btf/vmlinux-`uname -r`
    if [ ! -f "$source_path" ]; then
        echo "target vmlinux file not exist: vmlinux-`uname -r`"
        exit -1
    fi
    cp $source_path ${btf_path}
}

show_list() {
    ls ${SYSAK_WORK_PATH}/tools/vmlinux-btf
}

while getopts 'd:lh' OPT; do
    case $OPT in
    "h")
        usage
        exit 0
        ;;
    "d")
        btf_dir=$OPTARG
        btf_path=${btf_dir}/vmlinux-$(uname -r)

        ;;
    "l")
        show_list
        exit 0
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
