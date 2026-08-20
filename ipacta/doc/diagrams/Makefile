SVG := $(wildcard *.svg)
PNG := $(SVG:.svg=.png)

INKSCAPE ?= inkscape
DPI = 96

all: $(PNG)

%.png: %.svg
	$(INKSCAPE) -d $(DPI) $< -o $@

clean:
	rm -f $(PNG)

.PHONY: all clean
