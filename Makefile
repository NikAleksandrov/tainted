C=/usr/bin/gcc
CFLAGS=-c -Wall
RM=/bin/rm
LDFLAGS=
SOURCES=tainted.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=tainted

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	$(RM) $(EXECUTABLE) $(EXECUTABLE).o
