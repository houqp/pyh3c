# -*- coding:utf-8 -*-
#!/usr/bin/env python

import gettext
import locale
import os

#gettext.bindtextdomain('pyh3c', './locale')
#gettext.textdomain('pyh3c')

DEFAULT_LANGUAGES = os.environ.get('LANG', '').split(':')
#LANG = ['zh_CN']
LANG = DEFAULT_LANGUAGES
APP_NAME = 'pyh3c'
#LOCALE_DIR = './i18n'
LOCALE_DIR = '/usr/share/locale'

gettext.install(APP_NAME)
gettext.find(APP_NAME, LOCALE_DIR, LANG)
gettext.textdomain(APP_NAME)
gettext.bind_textdomain_codeset(APP_NAME, 'UTF-8')
language = gettext.translation(APP_NAME, LOCALE_DIR, LANG, fallback=True)

