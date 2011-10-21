PyH3C
=====

PyH3C is a program for passing h3c authentication in SYSU east campus.

Currently, python 3 is not supported. Also Windows operating system is not supported because I do not know how to acquire IP under this user friendly system. ;-P

Dependencies
------------

You need to install `libdnet` and `pypcap` library before you run the program.

So for **Ubuntu** users:

```bash
$ apt-get install python-pypcap python-dumbnet
```

If you're using pyhton with version lower than 2.7, you will also need to install argparse:

```bash
$ apt-get install python-argparse
```

For **Gentoo** users:

```bash
$ emerge pypcap libdnet 
```

If you're using pyhton with version lower than 2.7, you will also need to install argparse:

```bash
$ emerge argparse
```

For **ArchLinux** users: 

You should first have `AUR` correctly configured and install `yaourt`(there's no reason not to use it, XD), then,

```bash
$ yaourt -S pypcap-svn libdnet
```

Sorry for coming along with lots of dependencies. :-( I will clean this up when I have time.


Installation
------------

Run the `setup.py` script which is contained in this program's directory

```bash
$ sudo python setup.py install
```

If you need Chinese translation, issue following command:

```bash
$ cd pyh3c/po && sudo make install
```


Usage
-----

It is recommended to use configuration file for setup. Please checkout pyh3c.conf.example for examples.

PyH3C use `pyh3c.conf` as configuration file and it should be put in /etc/

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


