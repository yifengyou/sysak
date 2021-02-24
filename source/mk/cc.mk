objs := $(foreach n, $(mods), $(OBJPATH)/$(n)) 

$(target): $(objs)
	g++ -o $(OBJPATH)/tools/$@ $^ -L$(OBJPATH)/lib $(LDFLAGS)

$(objs): $(mods)

$(mods): %.o : %.cpp
	g++ -I. -c -o $(OBJPATH)/$@ $<
