#ifndef DISPLAYER_H
#define DISPLAYER_H

#include <memory>
#include "display/Outputer.hpp"

namespace pingtrace
{
class Displayer
{
protected:
	std::shared_ptr<OutPuter> output;

public:
	Displayer(std::shared_ptr<OutPuter> &output) : output(output) {}
};
}; // namespace pingtrace

#endif