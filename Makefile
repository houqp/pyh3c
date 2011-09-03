.PHONY:clean all

all:
	markdown README.md > index.html

clean:
	rm -rf *.html
