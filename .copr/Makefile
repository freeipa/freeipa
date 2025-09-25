srpm:
	# Setup development environment
	echo "Installing FreeIPA development dependencies"
	cp freeipa.spec.in freeipa.spec
	dnf builddep -y --best --allowerasing --setopt=install_weak_deps=False freeipa.spec > ${outdir}/builddep.log 2>&1

	# Fetch webui
	git submodule update --init --recursive

	# Run autoconf
	autoreconf -i
	./configure --enable-silent-rules

	# Generate SRPMS
	make srpms

	if [[ "${outdir}" != "" ]]; then \
		mv rpmbuild/SRPMS/* ${outdir}; \
	fi
