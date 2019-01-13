CXX := gcc
CXXFLAGS := -lpcap -lpthread -Wall
GREEN :=\033[0;32m
NC :=\033[0m

all: finale

finale: detector

detector: port_scan_detector.c
	$(CXX) $(CXXFLAGS) port_scan_detector.c -o detector

finale:
	@echo "${GREEN}Success!${NC}\nUsage:\n./detector"

clean:
	rm -f *.o *.out
