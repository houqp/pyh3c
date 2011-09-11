PyH3C
=====

PyH3C is a program for passing h3c authentication in SYSU east campus.

Currently, python 3 is not supported. Also Windows operating system is not supported because I do not know how to acquire IP under this user friendly system. ;-P

Dependencies
------------

You need to install dpkt, libdnet argparse and pypcap python library before you run the program.

So for *Ubuntu* users:

```bash
$ sudo apt-get install python-pypcap python-dpkt python-dumbnet python-argparse
```

For *Gentoo* users:

```bash
$ emerge pypcap dpkt libdnet argparse
```

When you emerge libdnet, remember to have python use flag turned on (It's turned on by default).

For *ArchLinux* users: 

You should first have `AUR` correctly configured and install `yaourt`(there's no reason not to use it, XD), then,

```bash
$ yaourt -S pypcap-svn dpkt libdnet
```

Sorry for coming along with lots of dependencies. :-( I will clean this up when I have time.


Installation
------------

Run the `setup.py` script which is contained in this program's directory

```bash
$ sudo python setup.py install
```


Usage
-----

It is recommended to use configuration file for setup. Please checkout pyh3c.conf.example for examples.

You must run the program with root privilege:

```bash
$ sudo pyh3c
```

If you want to use command line arguments to setup PyH3C, check out -h argument for more information.


Plugins
-------

PyH3C comes with a simple plugin system. For more instructions on writing plugins, please checkout the template file under *plugins* directory.


Contributing
------------

Any contribution is welcome.

It will be great if you can help me make it a better software.


