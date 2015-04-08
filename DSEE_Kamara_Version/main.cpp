#define _CRT_SECURE_NO_WARNINGS

#include <iostream>

#include <sha.h>
#include <osrng.h>
#include <hex.h>

#pragma comment(lib, "cryptlib.lib")

using namespace std;
using namespace CryptoPP;

string sha256(string text)
{
	SHA256 hash;
	//string text = "Test";
	string result;
	string encoded;

	StringSource ss1(text, true,
		new HashFilter(hash,
		new StringSink(result)
		) // HashFilter 
		); // StringSource
	//cout << "DEBUG: result.size() = " << result.size() << endl;

	StringSource ss2(result, true,
		new HexEncoder(
		new StringSink(encoded)
		) // HexEncoder
		); // StringSource

	//cout << "Data: " << text << endl << "SHA-256 hash: " << encoded << endl;

	return result;
}

void HMAC_SHA256()
{

}


int main()
{
	return 0;
}