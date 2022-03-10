#!/bin/bash
# author: Shuyi Cheng
# email: chengshuyi@linux.alibaba.com

zip_path=${SYSAK_WORK_PATH}/tools/BTF/btf.7z
btf_dir=${SYSAK_WORK_PATH}/tools
btf_path=${btf_dir}/vmlinux-$(uname -r)
vmlinux_path=""

usage() {
    echo "sysak btf: Extract the btf file to the specified directory"
    echo "options: -h, help information"
    echo "         -d, Specify the path, default directory path: ${btf_dir}"
    echo "         -l, show vmlinux btf list"
    echo "         -g, Specify the vmlinux file path, which is used to generate btf. The generated btf file path is: ${btf_path} "
}

extract_btf() {
    source_path=${SYSAK_WORK_PATH}/tools/vmlinux-btf/vmlinux-`uname -r`
    if [ ! -f "$source_path" ]; then
        echo "target vmlinux file not exist: vmlinux-`uname -r`"
        exit -1
    fi
    cp $source_path ${btf_path}
}

generate_btf() {
    if [ ! -f "$vmlinux_path" ]; then
        echo "vmlinux file not exist: $vmlinux_path}"
    fi
    ${btf_dir}/pahole -J --kabi_prefix=__UNIQUE_ID_rh_kabi_hide --btf_encode_detached=${btf_path} ${vmlinux_path}
    echo "btf file has been generated, the path is: ${btf_path}"
}

show_list() {
    ls ${SYSAK_WORK_PATH}/tools/vmlinux-btf
}

while getopts 'g:d:lh' OPT; do
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
    "g")
        vmlinux_path=$OPTARG
        generate_btf
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
