PyH3C
=====

PyH3C is a program for passing h3c authentication in SYSU east campus.

Currently, python 3 is not supported. Also Windows operating system is not supported because I do not know how to acquire IP under this user friendly system. ;-P


Installation
-------

You need to install dpkt, libdnet and pypcap python library before you run the program.

So for Ubuntu users:

    apt-get install python-pypcap python-dpkt python-dumbnet

For Gentoo users:

    emerge pypcap dpkt libdnet

When you emerge libdnet, remember to have python use flag turn on (It's turned on by default).

Sorry for coming along with lots of dependencies. :-(


Usage
-----

It is recommended to use configuration file for setup. Please checkout pyh3c.conf.example for examples.

You must run the program with root privilege:

    sudo python pyh3c.py

If you want to use command line arguments to setup PyH3C, check out -h argument for more information.

Plugins
-------

PyH3C comes with a simple plugin system. For more instructions on writing plugins, please checkout the template file under *plugins* directory.


Contributing
------------

Any contribution is welcome.

It will be great if you can help me make it a better software.


