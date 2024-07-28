all: ufsend ufrec

ufsend: 
	g++ -o ufsend ufsend.cpp -fpermissive -lcrypto

ufrec: 
	g++ -o ufrec ufrec.cpp -fpermissive -lcrypto 
