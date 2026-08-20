# ipacta-comprehensive.md's own "Further Reading" section links to
# these files by internal anchor, so they must be appended in this
# exact order (matching that section) for the links to resolve to the
# right place -- see the discovered anchors in the "Further Reading"
# section itself if this list ever needs to change.
MD_SRC = ../ipacta-comprehensive.md \
	appendix-divider.md \
	../overview.md \
	../configuration.md \
	../ca-engine.md \
	../certificate-lifecycle.md \
	../ocsp-crl.md \
	../acme.md \
	../storage.md \
	../rest-api.md \
	../security.md \
	../installation.md \
	../utilities.md \
	../subca.md
PANDOC_OPTS = -f markdown -t latex --template=pandoc-template.tex -V fontsize=11pt -V geometry:margin=2.5cm --lua-filter=pandoc-filters.lua

all: doc

doc: pdf
	pandoc -f latex -t odt -o ipacta.odt ipacta.tex

tex:
	pandoc $(PANDOC_OPTS) -o ipacta.tex $(MD_SRC)

pdf: tex
	-pdflatex --shell-escape -interaction=nonstopmode ipacta.tex
	-pdflatex --shell-escape -interaction=nonstopmode ipacta.tex
	@test -s ipacta.pdf

clean:
	rm -f ipacta.odt
	rm -f ipacta.tex ipacta.aux ipacta.blg ipacta.log ipacta.pdf
	rm -rf svg-inkscape

.PHONY: all doc tex pdf clean
