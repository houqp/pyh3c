.PHONY:clean all

all:
	mdpage -t index.tp -m index.md -o index.html

clean:
	rm -rf *.html
