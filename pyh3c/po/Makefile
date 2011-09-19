.PHONY:all clean

DOMAIN = pyh3c

all:update-po mo

install:
	for po in *.po; do \
		lingua=`basename $$po .po` ; \
		msgfmt -o $$lingua.mo $$po ; \
		cp $$lingua.mo /usr/share/locale/$$lingua/LC_MESSAGES/$(DOMAIN).mo; \
	done

uninstall:
	find /usr/share/locale/ -iname pyh3c.mo | xargs rm

update-po:pot
	for po in *.po; do \
		lingua=`basename $$po .po`; \
		mv $$lingua.po $$lingua.old.po; \
		if msgmerge -N --output-file=$$lingua.po $$lingua.old.po $(DOMAIN).pot; then \
			rm $$lingua.old.po; \
		else \
			rm -f $$lingua.po; \
			mv $$lingua.old.po $$lingua.po; \
		fi \
	done

pot:
	xgettext --from-code=utf-8 --language=Python --keyword=_ --output=pyh3c.pot `find ../ -iname "*.py"`

po:pot
	msginit --input=pyh3c.pot --locale=zh_CN.utf8 --output-file=zh_CN.po

mo:
	for po in *.po; do \
		lingua=`basename $$po .po` ; \
		msgfmt -o $$lingua.mo $$po ; \
		mkdir -p ../i18n/$$lingua/LC_MESSAGES/ ; \
		ln -f $$lingua.mo ../i18n/$$lingua/LC_MESSAGES/$(DOMAIN).mo ; \
	done

clean:
	rm -rf ../i18n ./pyh3c.pot ./*.mo
