#include "netmodel/NetModel.h"
#include "ecs/NetModelEcs.hpp"
#include "namespace/NetModelNameSpace.hpp"

namespace pingtrace {

std::shared_ptr<NetModel> NetModel::init(options *opt, uint32_t id)
{
	in_addr_t dst;
	sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	if ((dst = inet_addr(opt->ip.c_str())) == (in_addr_t)(-1)) {
		throw ping_exception("invalid IPv4 dotted decimal notation", -EINVAL);
	}
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = dst;
	if (opt->is_namespace) {
		return std::make_shared<NamespaceNetModel>(opt, addr);
	}
	return std::make_shared<EcsNetModel>(opt, addr, id);
}
} // namespace netmodel_helper