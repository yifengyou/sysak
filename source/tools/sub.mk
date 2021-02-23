dirs := $(shell find . -maxdepth 1 -type d)
dirs := $(basename $(patsubst ./%,%,$(dirs)))

SUBDIRS := $(dirs)

.PHONY: subdirs $(SUBDIRS) clean

subdirs: $(SUBDIRS)
$(SUBDIRS):
	make -C $@

