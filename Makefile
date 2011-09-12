.PHONY:clean all

all:
	mdpage -t index.tp -o index.html

clean:
	rm -rf *.html
