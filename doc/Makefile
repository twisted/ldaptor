DIAS:= \
	chat-bind.dia \
	chat-search.dia \
	chat-search-pipeline.dia \
	chat-unbind.dia \
	ldapfilter-as-tree.dia \
	ldap-is-a-tree.dia \
	overview.dia

DIAPNG:=$(DIAS:%.dia=%.dia.png)

DOCBOOK:=ldap-intro.xml
SLIDES:=addressbook-slides.xml

GENERATED:=\
	$(DOCBOOK:%.xml=%/index.html) \
	$(SLIDES:%.xml=%/index.html) \
	$(DIAPNG) \
	api

XMLIFY:=sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'

all:: $(GENERATED)

clean:
	rm -rf \
		$(GENERATED) \
		ldap-intro \
		$(DIAPNG:%=%.tmp) \
		addressbook-ldif \
		addressbook-session \
		addressbook-slides

rsync: $(GENERATED)
	rsync -a $(DOCBOOK:%.xml=%.html) $(SLIDES:%.xml=%) $(DIAPNG) pyramid.twistedmatrix.com:public_html/ldap-intro/
	rsync -a --exclude '*.pyc' --exclude SCCS --exclude '*~' examples/addressbook/{[0-9]*,README.txt,server}  pyramid.twistedmatrix.com:public_html/ldap-intro/addressbook/

$(DOCBOOK:%.xml=%/index.html): %/index.html: %.xml
	install -d -m0755 '$(@D)'
	xsltproc  --nonet \
		/usr/share/sgml/docbook/stylesheet/xsl/nwalsh/xhtml/docbook.xsl \
		$< \
		>$@.tmp
	mv $@.tmp $@

ldap-intro/index.html: \
	ldap-intro/ldap-is-a-tree.dia.png \
	ldap-intro/ldapfilter-as-tree.dia.png \
	ldap-intro/chat-bind.dia.png \
	ldap-intro/chat-search.dia.png \
	ldap-intro/chat-search-pipeline.dia.png \
	ldap-intro/chat-unbind.dia.png

ldap-intro/%.dia.png: %.dia.png
	install -d -m0755 '$(@D)'
	install -m0644 $< $@.tmp
	mv $@.tmp $@

addressbook-ldif/%.xml: examples/addressbook/server/%.ldif
	install -d -m0755 '$(@D)'
	$(XMLIFY) <$< >$@.tmp
	mv $@.tmp $@

addressbook-session/session-%.xml: examples/addressbook/01_repl/session-%
	install -d -m0755 '$(@D)'
	$(XMLIFY) <$< >$@.tmp
	mv $@.tmp $@

addressbook-slides/%/addressbook-py.html: \
	examples/addressbook/%/addressbook.py tags.j2h
	install -d -m0755 '$(@D)'
	( echo '<font size="+1">' && source-highlight --out-format=xhtml --src-lang=python && echo '</font>' ) <$< >$@.tmp
	mv $@.tmp $@

addressbook-slides/%/addressbook-tac.html: \
	examples/addressbook/%/addressbook.tac tags.j2h
	install -d -m0755 '$(@D)'
	( echo '<font size="+1">' && source-highlight --out-format=xhtml --src-lang=python && echo '</font>' ) <$< >$@.tmp
	mv $@.tmp $@

addressbook-slides/%/searchform-xhtml.html: \
	examples/addressbook/%/searchform.xhtml
	install -d -m0755 '$(@D)'
	( echo '<pre>' && sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g;' && echo '</pre>' ) <$< >$@.tmp
	mv $@.tmp $@

addressbook-slides/index.html: \
	ldapentry-vs-oo.xml search-inputs.xml

ldap-intro.html: \
	ldapentry-vs-oo.xml search-inputs.xml

$(SLIDES:%.xml=%/index.html): %/index.html: %.xml \
	slides-driver.xsl \
	Makefile $(DIAPNG) \
	addressbook-ldif/doe.xml \
	addressbook-ldif/smith.xml \
	addressbook-session/session-01.xml \
	addressbook-session/session-02.xml \
	addressbook-session/session-03.xml \
	addressbook-session/session-04.xml \
	addressbook-session/session-05.xml \
	addressbook-session/session-06.xml \
	addressbook-session/session-07.xml \
	addressbook-session/session-08.xml \
	addressbook-session/session-09.xml \
	slide-style.css \
	addressbook-slides/02_script/addressbook-py.html \
	addressbook-slides/07_easy/addressbook-py.html \
	addressbook-slides/07_easy/searchform-xhtml.html \
	addressbook-slides/07_easy/addressbook-tac.html
	install -d -m0755 '$(@D)'
	cp -ar /usr/share/sgml/docbook/custom/slides/3.2.0/graphics '$(@D)'
	cp -ar /usr/share/sgml/docbook/custom/slides/3.2.0/browser '$(@D)'
	patch '$(@D)/browser/overlay.js' <overlay.js.patch
	cp $(DIAPNG) '$(@D)'
	cp slide-style.css '$(@D)'
	# TODO --nonet
	cd '$(@D)' && xsltproc \
		--stringparam keyboard.nav 1 \
		--stringparam overlay 1 \
		--stringparam output.indent yes \
		--stringparam graphics.dir graphics \
		--stringparam script.dir browser \
		../slides-driver.xsl \
		'$(addprefix ../,$<)'
	perl -pi -e '\
		s{<a href="(.*?)" target="_top">Click me!</a>}{<iframe width=900 height=600 src="$$1" />}g; \
		' \
		'$(@D)'/foil*.html

%.dia.png: %.dia
	dia --export-to-format=png-libart --export=$@.tmp $<
	mv $@.tmp $@

api:
	epydoc \
	        -o api \
		-n Ldaptor \
	        -u http://tv.debian.net/software/ldaptor/ \
		$$(find ../ldaptor \( -name SCCS -prune \) -o -name '*.py' -print)

.PHONY: api
