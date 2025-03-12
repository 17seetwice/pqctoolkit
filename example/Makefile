CXX = g++
CXXFLAGS = -Werror -Wformat=2 -Wsign-compare -Wwrite-strings -Wvla -Wshadow -Wtype-limits \
           -Wmissing-field-initializers -ggdb -Wall -fvisibility=hidden -fno-common \
           -Wno-free-nonheap-object -Wimplicit-fallthrough -Wformat-signedness \
           -Wnon-virtual-dtor -std=gnu++14

INCLUDES = -I./libs/include -I./
LIBSSL = -lssl
LIBCRYPTO = -lcrypto
LIBOQS = -loqs

# Source files
SRCS_SERVER = server.c ssl_utils.c
SRCS_CLIENT = client.c ssl_utils.c

# Object files
OBJS_SERVER = $(SRCS_SERVER:.c=.o)
OBJS_CLIENT = $(SRCS_CLIENT:.c=.o)

# Output binaries
TARGET_SERVER = server
TARGET_CLIENT = client

# Build both client and server (default target)
all: server client

# Build the server executable
server: $(OBJS_SERVER)
	$(CXX) $(OBJS_SERVER) -o $(TARGET_SERVER) -L./libs $(LIBSSL) $(LIBCRYPTO) $(LIBOQS) $(CXXFLAGS) $(INCLUDES)

# Build the client executable
client: $(OBJS_CLIENT)
	$(CXX) $(OBJS_CLIENT) -o $(TARGET_CLIENT) -L./libs $(LIBSSL) $(LIBCRYPTO) $(LIBOQS) $(CXXFLAGS) $(INCLUDES)


# Compile the source files into object files
%.o: %.c
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# Clean up generated files
clean:
	rm -f $(OBJS_SERVER) $(OBJS_CLIENT) $(TARGET_SERVER) $(TARGET_CLIENT)

# Order of targets
.PHONY: clean all server client
