NULL =

SCHEMA_DIR = $(top_builddir)/install/gc/AD
CONVERT_SCHEMA = $(top_builddir)/install/gc/convert-schema
SCHEMA_FILES = 							\
        $(SCHEMA_DIR)/AD_DS_Attributes__Windows_Server_2016.ldf \
	$(SCHEMA_DIR)/AD_DS_Classes__Windows_Server_2016.ldf    \
	$(NULL)

gcbasedir = $(IPA_DATA_DIR)/gc/base
dist_gcbase_DATA =                          \
        00-ad-bootstrap-template.ldif       \
	00-ad-indices.ldif                  \
	00-ad-schema-2016.ldif              \
	objectguid.ldif                     \
	default-aci.ldif                    \
	$(NULL)

.PHONY: $(SCHEMA_FILES)
00-ad-schema-2016.ldif: $(CONVERT_SCHEMA) $(SCHEMA_FILES)
	@$(CONVERT_SCHEMA) $(SCHEMA_FILES) >$@

