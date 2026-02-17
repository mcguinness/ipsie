GEM_BIN    := $(shell gem environment gemdir)/bin
KRAMDOWN   = $(GEM_BIN)/kramdown-rfc
XML2RFC    = xml2rfc

SPECS = ipsie-session-lifecycle-commands

MD_SOURCES := $(addsuffix .md,$(SPECS))
HTML_FILES := $(addsuffix .html,$(SPECS))
XML_FILES  := $(addsuffix .xml,$(SPECS))

.PHONY: all clean install-deps html xml

all: html

html: $(HTML_FILES)

xml: $(XML_FILES)

%.xml: %.md
	$(KRAMDOWN) $< > $@

%.html: %.xml
	$(XML2RFC) --html $<

clean:
	rm -f $(HTML_FILES) $(XML_FILES)

install-deps:
	gem install kramdown-rfc2629
	pip3 install xml2rfc
