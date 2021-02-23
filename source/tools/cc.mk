objs := $(foreach n, $(mods), $(OBJPATH)/$(n)) 

$(target): $(objs)
	g++ -o $(OBJPATH)/tools/$@ $^

$(objs): $(mods)

$(mods): %.o : %.cpp
	g++ -c -o $(OBJPATH)/$@ $<
