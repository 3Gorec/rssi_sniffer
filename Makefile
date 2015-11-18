BUILD_DIR=build/
SRC_DIR=src/
CPP_SOURCES=$(wildcard $(SRC_DIR)*.cpp)
CPP_SOURCES:=$(patsubst $(SRCDIR)%,%,$(CPP_SOURCES))
C_SOURCES=$(wildcard $(SRC_DIR)*.c)
C_SOURCES:=$(patsubst $(SRCDIR)%,%,$(C_SOURCES))
C_OBJECTS=$(C_SOURCES:.c=.o)
C_OBJECTS:=$(patsubst src/%,%,$(C_OBJECTS))
CPP_OBJECTS=$(CPP_SOURCES:.cpp=.o)
CPP_OBJECTS:=$(patsubst src/%,%,$(CPP_OBJECTS))
OBJECTS=$(CPP_OBJECTS) $(C_OBJECTS)
INCDIR=inc
LDFLAGS=-lprotobuf -lpthread -lrt
TARGET=rssi_sniffer

all: build

build: $(TARGET)
	@echo $(CPP_SOURCES)

$(TARGET): $(CPP_OBJECTS) $(C_OBJECTS) prepare
	@echo $(OBJECTS)
	$(CXX) -o $(BUILD_DIR)$@ $(patsubst %,$(BUILD_DIR)%,$(OBJECTS)) $(LDFLAGS)

prepare:
	@if [ ! -d $(BUILD_DIR) ] ; then mkdir $(BUILD_DIR) ;fi

%.o: $(SRC_DIR)%.cpp prepare
	$(CXX) $(CXXFLAGS) -o $(BUILD_DIR)$@ -c $< -I$(INCDIR) 

%.o: $(SRC_DIR)%.c prepare
	$(CC) $(CFLAGS) -o $(BUILD_DIR)$@ -c $< -I$(INCDIR) 


clean:
	rm -Rf build
