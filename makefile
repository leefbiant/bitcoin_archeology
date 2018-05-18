all:
	g++ -std=c++11 -Wall -g -O2 -o bitcoin_archeology main.cc  ckey.cc -lssl -lcrypto
clean:
	rm -rf bitcoin_archeology
