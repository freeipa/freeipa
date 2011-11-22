FILE=guide.org
XML=$(addsuffix .xml, $(basename $(FILE)))
PDF=$(addsuffix .pdf, $(basename $(FILE)))
TXT=$(addsuffix .txt, $(basename $(FILE)))
HTML=$(addsuffix .html, $(basename $(FILE)))
FO=$(addsuffix .fo, $(basename $(FILE)))

all: $(PDF) $(TXT) $(HTML)
	@echo Finished: $? are created

plain: $(FILE)
	@echo -n "Building HTML, Docbook, and plain text ..."
	@emacs -batch -q --no-site-file -eval "(require 'org)" \
     --visit $< -f org-export-as-html \
     --visit $< -f org-export-as-docbook \
     --visit $< -f org-export-as-ascii 2>/dev/null
	@echo "done, see $(HTML), $(XML), $(TXT)"

$(TXT): plain

$(HTML): plain

$(XML): plain

$(FO): $(XML)
	@xmlto --skip-validation fo $< 2>/dev/null

$(PDF): $(FO)
	@echo -n "Building PDF ... "
	@fop -fo $< -pdf $@ -l en -a 2>/dev/null
	@echo "done, see $(PDF)"

.PHONY: clean

clean:
	@rm -f *.html *.txt *.xml *.fo *.pdf *~
