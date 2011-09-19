# Copyright 1999-2011 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI=3
PYTHON_DEPEND="2"

inherit distutils git-2

DESCRIPTION="A program for passing h3c authentication in SYSU east campus."
HOMEPAGE="http://houqp.github.com/pyh3c"
SRC_URI=""
EGIT_REPO_URI="git://github.com/houqp/pyh3c.git"

LICENSE="GPL"
SLOT="0"
KEYWORDS="~amd64 ~x86"
IUSE=""

# argparse for python lower than 2.7
if [ $(python_get_version --major) -lt 2 ] && [ $(python_get_version --minor) -lt 7 ];then
	CON_DEP="dev-python/argparse"
else
	CON_DEP=""
fi

DEPEND="dev-python/dpkt
	  dev-python/pypcap
	  dev-libs/libdnet
	  ${CON_DEP}"
RDEPEND="${DEPEND}"

DOCS="README.md AUTHORS pyh3c/pyh3c.conf.example"

src_prepare() {
	git checkout developing
}

src_install() {
	distutils_src_install
	cd pyh3c/po && emake  DESTDIR="${D}usr/share/locale" install || die "failed to install translations."
}

