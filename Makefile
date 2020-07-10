#
PREFIX	?= /usr/local
SUBDIRS	= src

all clean veryclean install::
		for d in $(SUBDIRS); do PREFIX=$(PREFIX) $(MAKE) -C $$d $@ || exit 1; done
clean::;	find . -name '*~' | xargs rm -f
veryclean::	clean
