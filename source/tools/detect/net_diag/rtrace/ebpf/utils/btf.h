#ifndef __RTRACE_UTILS_BTF_H
#define __RTRACE_UTILS_BTF_H

struct btf *btf_load(char *btf_custom_path);

int btf_func_proto_find_param(struct btf *btf, int func_proto_id,
                              const char *type_name, const char *param_name);
int btf_func_proto_find_param_pos(struct btf *btf, int func_proto_id,
                                  const char *type_name, const char *param_name);
// Find func proto type id by func name.
int btf_find_func_proto_id(struct btf *btf, const char *func_name);
// Find member in struct/union by member name.
const struct btf_member *btf_find_member(struct btf *btf, int typeid,
                                         const char *target_member_name, int *offset);
bool btf_typeid_has_ptr(const struct btf *btf, int id);

#endif
