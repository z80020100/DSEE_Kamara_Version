#define _CRT_SECURE_NO_WARNINGS

#include <iostream>

#include <sha.h>
#include <osrng.h>
#include <hex.h>
#include <hmac.h>

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

void HMAC_SHA_256(byte *user_key, int user_key_len, string plain)
{
	SecByteBlock key(user_key, user_key_len);
	string mac, encoded;

	// Pretty print key
	encoded.clear();
	StringSource ss1(key, key.size(), true,
		new HexEncoder(
		new StringSink(encoded)
		) // HexEncoder
		); // StringSource

	cout << "key: " << encoded << endl;
	cout << "plain text: " << plain << endl;

	try
	{
		HMAC< SHA256 > hmac(key, key.size());

		StringSource ss2(plain, true,
			new HashFilter(hmac,
			new StringSink(mac)
			) // HashFilter      
			); // StringSource
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	// Pretty print
	encoded.clear();
	StringSource ss3(mac, true,
		new HexEncoder(
		new StringSink(encoded)
		) // HexEncoder
		); // StringSource

	cout << "hmac: " << encoded << endl;
}

int main()
{
	byte key[16] = { 0 };
	HMAC_SHA_256(key, sizeof(key), "HMAC Test");

	return 0;
}