#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <errno.h>

#include "common.usr.h"
#include "utils/btf.h"

static bool btf_type_is_modifier(const struct btf_type *t)
{
    /* Some of them is not strictly a C modifier
	 * but they are grouped into the same bucket
	 * for BTF concern:
	 *   A type (t) that refers to another
	 *   type through t->type AND its size cannot
	 *   be determined without following the t->type.
	 *
	 * ptr does not fall into this bucket
	 * because its size is always sizeof(void *).
	 */
    switch (BTF_INFO_KIND(t->info))
    {
    case BTF_KIND_TYPEDEF:
    case BTF_KIND_VOLATILE:
    case BTF_KIND_CONST:
    case BTF_KIND_RESTRICT:
    // case BTF_KIND_TYPE_TAG:
        return true;
    }

    return false;
}

const struct btf_type *btf_type_skip_modifiers(const struct btf *btf,
                                               uint32_t id, uint32_t *res_id)
{
    const struct btf_type *t = btf__type_by_id(btf, id);

    while (btf_type_is_modifier(t))
    {
        id = t->type;
        t = btf__type_by_id(btf, t->type);
    }

    if (res_id)
        *res_id = id;

    return t;
}

const struct btf_type *btf_type_skip_ptr(const struct btf *btf, uint32_t id)
{
    const struct btf_type *t = btf__type_by_id(btf, id);
    while (btf_is_ptr(t))
        t = btf__type_by_id(btf, t->type);

    return t;
}

/* Similar to btf_type_skip_modifiers() but does not skip typedefs. */
static const struct btf_type *btf_type_skip_qualifiers(const struct btf *btf,
                                                       uint32_t id)
{
    const struct btf_type *t = btf__type_by_id(btf, id);

    while (btf_type_is_modifier(t) &&
           BTF_INFO_KIND(t->info) != BTF_KIND_TYPEDEF)
    {
        t = btf__type_by_id(btf, t->type);
    }

    return t;
}

bool btf_typeid_has_ptr(const struct btf *btf, int id)
{
    const struct btf_type *t;
    t = btf_type_skip_modifiers(btf, id, NULL);

    if (!btf_is_ptr(t))
        return false;
    return true;
}

const struct btf_member *btf_find_member(struct btf *btf, int typeid,
                                         const char *target_member_name, int *offset)
{
    const struct btf_type *t;
    const struct btf_member *m, *tmpm;
    const char *name;
    int i;
    
    t = btf__type_by_id(btf, typeid);
    while(btf_type_is_modifier(t) || btf_is_ptr(t)) {
        t = btf_type_skip_modifiers(btf, typeid, (uint32_t *)&typeid);
        t = btf_type_skip_ptr(btf, typeid);
    }
    m = btf_members(t);
    for (i = 0; i < btf_vlen(t); i++, m++)
    {
        name = btf__name_by_offset(btf, m->name_off);
        if (!name || !name[0])
        {
            // find embedded struct/union
            tmpm = btf_find_member(btf, m->type, target_member_name, offset);
            if (tmpm)
            {
                pr_dbg("find member: name-%s, off-%u, size-%llu\n", btf__name_by_offset(btf, tmpm->name_off), tmpm->offset, btf__resolve_size(btf, tmpm->type));
                *offset += m->offset;
                return tmpm;
            }
        }
        else if (strcmp(name, target_member_name) == 0)
        {
            pr_dbg("find member: name-%s, off-%u, size-%llu\n", btf__name_by_offset(btf, m->name_off), m->offset, btf__resolve_size(btf, m->type));
            *offset += m->offset;
            return m;
        }
    }

    pr_dbg("Unable to find %s(member) in %s(struct)\n", target_member_name, btf__name_by_offset(btf, t->name_off));
    return NULL;
}

struct btf *btf_load(char *btf_custom_path)
{
    struct btf *btf;
    int err;
    if (btf_custom_path != NULL)
        btf = btf__parse(btf_custom_path, NULL);
    else
        btf = libbpf_find_kernel_btf();

    err = libbpf_get_error(btf);
    if (err)
    {
        errno = -err;
        return NULL;
    }

    return btf;
}

static const char *btf_param_type_name(struct btf *btf, const struct btf_param *p)
{
    const struct btf_type *t;
    __s32 id = p->type;
    t = btf__type_by_id(btf, id);
    // todo: 过滤掉名字不是结构体类型的参数
    if (BTF_INFO_KIND(t->info) == BTF_KIND_PTR)
        t = btf__type_by_id(btf, t->type);

    if (BTF_INFO_KIND(t->info) == BTF_KIND_CONST)
        t = btf__type_by_id(btf, t->type);
    return btf__name_by_offset(btf, t->name_off);
}

int btf_func_proto_find_param(struct btf *btf, int func_proto_id,
                              const char *type_name, const char *param_name)
{
    const struct btf_type *t;
    const struct btf_param *p;
    const char *tmp_param_name, *tmp_type_name;
    int i;

    t = btf__type_by_id(btf, func_proto_id);
    if (t == NULL)
        return -EINVAL;

    for (i = 0; i < btf_vlen(t); i++)
    {
        p = btf_params(t) + i;
        tmp_param_name = btf__name_by_offset(btf, p->name_off);
        if (param_name && tmp_param_name && strcmp(param_name, tmp_param_name) == 0)
            return p->type;

        tmp_type_name = btf_param_type_name(btf, p);
        if (type_name && tmp_type_name && strcmp(type_name, tmp_type_name) == 0)
            return p->type;
    }
    return -ENOENT;
}

int btf_func_proto_find_param_pos(struct btf *btf, int func_proto_id,
                                  const char *type_name, const char *param_name)
{
    const struct btf_type *t;
    const struct btf_param *p;
    const char *tmp_param_name, *tmp_type_name;
    int i;

    t = btf__type_by_id(btf, func_proto_id);
    if (t == NULL)
        return -EINVAL;

    for (i = 0; i < btf_vlen(t); i++)
    {
        p = btf_params(t) + i;
        tmp_param_name = btf__name_by_offset(btf, p->name_off);
        if (param_name && tmp_param_name && strcmp(param_name, tmp_param_name) == 0)
            return i + 1;

        tmp_type_name = btf_param_type_name(btf, p);
        if (type_name && tmp_type_name && strcmp(type_name, tmp_type_name) == 0)
            return i + 1;
    }
    return -ENOENT;
}

int btf_find_func_proto_id(struct btf *btf, const char *func_name)
{
    const struct btf_type *t;
    int id;

    if (!btf && !func_name)
        return -EINVAL;

    id = btf__find_by_name_kind(btf, func_name, BTF_KIND_FUNC);
    if (id <= 0)
        return id;
    t = btf__type_by_id(btf, id);
    return t->type;
}