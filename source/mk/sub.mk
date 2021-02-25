exclude_dirs := include inc
dirs := $(shell find . -maxdepth 1 -type d)
dirs := $(basename $(patsubst ./%,%,$(dirs)))
dirs:=$(filter-out $(exclude_dirs),$(dirs))

SUBDIRS := $(dirs)

.PHONY: subdirs $(SUBDIRS) clean

subdirs: $(SUBDIRS)
$(SUBDIRS):
	make -C $@

