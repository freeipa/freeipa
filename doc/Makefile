# Minimal makefile for Sphinx documentation
#

# You can set these variables from the command line, and also
# from the environment for the first two.
PYTHON        ?= python3
VENVDIR       = ./.venv
SPHINXOPTS    ?= -W --keep-going -j auto
SPHINXBUILD   ?= PATH=$(VENVDIR)/bin:$$PATH sphinx-build
SOURCEDIR     = .
BUILDDIR      = _build

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
	@echo "  lint        to check and lint documentation"
	@echo "  venv        to create an isolated venv"

.PHONY: help Makefile

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

.PHONY: workshop-remote workshop-pull
workshop-remote:
	git remote add -f freeipa-workshop https://github.com/freeipa/freeipa-workshop.git
workshop-pull:
	git pull -s subtree freeipa-workshop master

.PHONY: lint
lint:
	$(MAKE) html SPHINXOPTS="$(SPHINXOPTS) -E -a"

.PHONY: distclean
distclean: clean
	rm -rf $(VENVDIR)

.PHONY: venv
venv:
	$(PYTHON) -m venv $(VENVDIR)
	$(VENVDIR)/bin/python3 -m pip install -U pip setuptools
	$(VENVDIR)/bin/python3 -m pip install -U -r ./requirements.txt
