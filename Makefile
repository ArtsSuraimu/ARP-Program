CC=gcc
CFLAGS=-w
LDFALGS=
TARGET=run

SOURCES=src/arp_final.c

OBJECTS=$(SOURCES:.c=.o)


all: $(SOURCES) $(TARGET)

$(TARGET): $(OBJECTS)
		$(CC) $(LDFALGS) $(OBJECTS) -o $@
.c.o:
		$(CC) -c $(CFLAGS) $< -o $@
clean:
	rm -rf $(SOURCES)
	rm -rf $(TARGET)

