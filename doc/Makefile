DOTS:= \
	ldap-is-a-tree.dot \
	ldapfilter-as-tree.dot \
	chat-bind.dot \
	chat-search.dot \
	chat-search-pipeline.dot \
	chat-unbind.dot

DOTEPS:=$(DOTS:%.dot=%.dot.eps)
DOTPNG:=$(DOTS:%.dot=%.dot.eps.png)

DOCBOOK:=ldap-intro.xml
SLIDES:=addressbook-slides.xml

GENERATED:=\
	$(DOCBOOK:%.xml=%.html) \
	$(SLIDES:%.xml=%/index.html) \
	$(DOTPNG)

XMLIFY:=sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'

all:: $(GENERATED)

install: api $(GENERATED)
	@[ -n '$(DESTDIR)' ] || { echo 'Please provide variable DESTDIR pointing to desired location of documents.' 1>&2; exit 1; }
	install -d -m0755 '$(DESTDIR)'
	cp -ar api addressbook-slides '$(DESTDIR)/'
	install -d -m0755 '$(DESTDIR)/ldap-intro'
	install -m0644 ldap-intro.html '$(DESTDIR)/ldap-intro/index.html'
	install -m0644 $(DOTPNG) '$(DESTDIR)/ldap-intro'
	find examples -name SCCS -prune -o -type f -exec \
		install -D -m0644 '{}' '$(DESTDIR)/{}' \;

install-%:
	@[ -n '$(DESTDIR)' ] || { echo 'Please provide variable DESTDIR pointing to desired location of documents.' 1>&2; exit 1; }
	install -d -m0755 '$(DESTDIR)'
	set -e; if [ -d 'examples.$*' ]; then \
		find 'examples.$*' -name SCCS -prune -o -type f -printf '%P\0' \
		| xargs -0 --replace -- \
			install -D -m0644 'examples.$*/{}' '$(DESTDIR)/examples/{}' ;\
	fi

clean:
	rm -f $(GENERATED)

rsync: $(GENERATED)
	rsync -a $(DOCBOOK:%.xml=%.html) $(SLIDES:%.xml=%) $(DOTPNG) pyramid.twistedmatrix.com:public_html/ldap-intro/
	rsync -a --exclude '*.pyc' --exclude SCCS --exclude '*~' examples/addressbook/{[0-9]*,README.txt,server}  pyramid.twistedmatrix.com:public_html/ldap-intro/addressbook/

$(DOCBOOK:%.xml=%.html): %.html: %.xml
	xsltproc  --nonet \
		/usr/share/sgml/docbook/stylesheet/xsl/nwalsh/xhtml/docbook.xsl \
		$< \
		>$@.tmp
	mv $@.tmp $@

addressbook-ldif/%.xml: examples/addressbook/server/%.ldif
	install -d -m0755 '$(@D)'
	$(XMLIFY) <$< >$@.tmp
	mv $@.tmp $@

addressbook-session/session-%.xml: examples/addressbook/01_repl/session-%
	install -d -m0755 '$(@D)'
	$(XMLIFY) <$< >$@.tmp
	mv $@.tmp $@

addressbook-slides/diffs/searchform-05-06.html:: \
	examples/addressbook/05_form/searchform.escaped.html \
	examples/addressbook/06_pretty/searchform.escaped.html


examples/addressbook/%.html: examples/addressbook/%.py tags.j2h
	( echo '<font size="+1">' && source-highlight --out-format=xhtml --src-lang=python && echo '</font>' ) <$< >$@.tmp
	mv $@.tmp $@

examples/addressbook/%/searchform.escaped.html: examples/addressbook/%/searchform.xhtml
	$(XMLIFY) <$< >$@.tmp
	mv $@.tmp $@

addressbook-slides/diffs/searchform-%.html:
	@[ -n '$^' ] || { echo 'Please provide variable dependencies for $@.' 1>&2; exit 1; }
	install -d -m0755 '$(@D)'
	echo '<font size="+1"><pre><tt>' >$@.tmp
	./htmldiff $^ >>$@.tmp
	echo '</tt></pre></font>' >>$@.tmp
	mv $@.tmp $@

addressbook-slides/diffs/addressbook-02-03.html:: \
	examples/addressbook/02_script/addressbook.html \
	examples/addressbook/03_webapp/addressbook.html

addressbook-slides/diffs/addressbook-03-04.html:: \
	examples/addressbook/03_webapp/addressbook.html \
	examples/addressbook/04_query/addressbook.html

addressbook-slides/diffs/addressbook-04-05.html:: \
	examples/addressbook/04_query/addressbook.html \
	examples/addressbook/05_form/addressbook.html

addressbook-slides/diffs/addressbook-05-06.html:: \
	examples/addressbook/05_form/addressbook.html \
	examples/addressbook/06_pretty/addressbook.html

addressbook-slides/diffs/addressbook-06-07.html:: \
	examples/addressbook/06_pretty/addressbook.html \
	examples/addressbook/07_easy/addressbook.html

addressbook-slides/diffs/addressbook-%.html:
	@[ -n '$^' ] || { echo 'Please provide variable dependencies for $@.' 1>&2; exit 1; }
	install -d -m0755 '$(@D)'
	./htmldiff $^ >$@.tmp
	mv $@.tmp $@

addressbook-slides/searchform-05_form.html: \
	examples/addressbook/05_form/searchform.xhtml
	install -d -m0755 '$(@D)'
	( echo '<pre><tt>' && $(XMLIFY) && echo '</tt></pre>' ) <$< >$@.tmp
	mv $@.tmp $@

addressbook-slides/addressbookpy-02_script.html: \
	examples/addressbook/02_script/addressbook.html
	install -d -m0755 '$(@D)'
	cp $< $@.tmp
	mv $@.tmp $@

addressbook-slides/index.html: \
	ldapentry-vs-oo.xml search-inputs.xml

ldap-intro.html: \
	ldapentry-vs-oo.xml search-inputs.xml

$(SLIDES:%.xml=%/index.html): %/index.html: %.xml \
	Makefile $(DOTPNG) \
	ldap-is-a-tree.dot.eps.small.png \
	addressbook-ldif/doe.xml \
	addressbook-ldif/smith.xml \
	addressbook-session/session-01.xml \
	addressbook-session/session-02.xml \
	addressbook-session/session-03.xml \
	addressbook-session/session-04.xml \
	addressbook-session/session-05.xml \
	addressbook-session/session-06.xml \
	addressbook-slides/diffs/addressbook-02-03.html \
	addressbook-slides/diffs/addressbook-03-04.html \
	addressbook-slides/diffs/addressbook-04-05.html \
	addressbook-slides/diffs/searchform-05-06.html \
	addressbook-slides/diffs/addressbook-06-07.html \
	addressbook-slides/searchform-05_form.html \
	addressbook-slides/addressbookpy-02_script.html
	install -d -m0755 '$(@D)'
	cp -ar /usr/share/sgml/docbook/custom/slides/3.2.0/graphics '$(@D)'
	cp -ar /usr/share/sgml/docbook/custom/slides/3.2.0/browser '$(@D)'
	patch '$(@D)/browser/overlay.js' <overlay.js.patch
	cp $(DOTPNG) '$(@D)'
	cp ldap-is-a-tree.dot.eps.small.png '$(@D)'
	# TODO --nonet
	cd '$(@D)' && xsltproc \
		--stringparam keyboard.nav 1 \
		--stringparam overlay 1 \
		--stringparam output.indent yes \
		--stringparam graphics.dir graphics \
		--stringparam script.dir browser \
		--stringparam css.stylesheet browser/slides.css \
		../slides-driver.xsl \
		'$(addprefix ../,$<)'
	perl -pi -e 's{<a href="(.*?)" target="_top">Click me!</a>}{<iframe width=900 height=600 src="$$1" />}g' \
		'$(@D)'/foil*.html

%.dot.eps: %.dot
	dot -Tps -o $@.tmp $<
	mv $@.tmp $@

%.eps.png: %.eps
	convert $< png:$@.tmp
	mv $@.tmp $@

%.eps.small.png: %.eps
	convert $< -resize 900x600 png:$@.tmp
	mv $@.tmp $@

api:
	epydoc \
	        -o api \
		-n Ldaptor \
	        -u http://tv.debian.net/software/ldaptor/ \
		$$(find ../ldaptor \( -name SCCS -prune \) -o -name '*.py' -print)

.PHONY: api
