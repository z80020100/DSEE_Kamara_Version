#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <random>
#include <dirent.h>
#include <fstream>

#include <sha.h>
#include <osrng.h>
#include <hex.h>
#include <hmac.h>
#include <cmac.h>

#pragma comment(lib, "cryptlib.lib")

#define ARRAY_SIZE 6
#define FREE_SIZE 2
#define SEARCH_TABLE_SIZE 65536
#define DELETE_TABLE_SIZE 65536
#define FREE "\"free\""

using namespace std;
using namespace CryptoPP;

inline void string_to_byte(byte *b_text, string s_text, int b_text_len);  // parse a string raw data to an array

/*string sha256(string text)
{
	return text;
}*/
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

inline string hex_encoder(string raw)
{
	string hex;
	StringSource ss2(raw, true,
		new HexEncoder(
		new StringSink(hex)
		) // HexEncoder
		); // StringSource
	return hex;
}

string HMAC_SHA_256(byte *user_key, int user_key_len, string plain)
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

	//cout << "key: " << encoded << endl;
	//cout << "plain text: " << plain << endl;

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

	//cout << "hmac: " << encoded << endl;

	return mac;
}

string CMAC_AES_128(byte *user_key, int user_key_len, string plain) // user_key_len must be equal to AES::DEFAULT_KEYLENGTH
{
	//byte user_key[16] = {0x00};
	SecByteBlock key(user_key, user_key_len);

	//string plain = "CMAC Test";
	string mac, encoded;

	// Pretty print key
	encoded.clear();
	StringSource ss1(key, key.size(), true,
		new HexEncoder(
		new StringSink(encoded)
		) // HexEncoder
		); // StringSource

	//cout << "key: " << encoded << endl;
	//cout << "plain text: " << plain << endl;

	try
	{
		CMAC< AES > cmac(key.data(), key.size());

		StringSource ss2(plain, true,
			new HashFilter(cmac,
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

	//cout << "cmac: " << encoded << endl;

	return mac;
}

int F(byte *user_key, int user_key_len, string keyword, int unit_bytes, int index) // hash function
{
	string cmac = CMAC_AES_128(user_key, user_key_len, keyword);
	byte temp[16];
	string_to_byte(temp, cmac, 16);
	unsigned short int *ptr_2byte = NULL;
	if (unit_bytes == 2)
	{
		ptr_2byte = (unsigned short int*)temp;
	}
	return ptr_2byte[index];
}

struct search_array //As, for each keyword, 40 bytes
{
	char id[32]; // the ID of the file, use sha256(file_name) as ID
	int addr_s_next; // the address of the next node in search array for a keyword
	int r; // for free As node, this is pointer to free Ad node
};

struct search_table // Ts, for each keyword, 8 bytes
{
	int addr_s_N_first; // the address of the first node in search array for a keyword
	int addr_d_N_first_dual; // the address of the first node in deletion array whose fourth entry points to the first node in search array for a keyword
};

struct del_array // Ad, for each file, 32 bytes
{
	int addr_d_next; // the address of the next node in deletion array for a file f
	int addr_d_prev_file; // the address of the fourth entry in deletion array which is points to the node for the next file f_+1 and keyword w
	int addr_d_next_file; // the address of the fourth entry in deletion array which is points to the node for the previous file f_+1 and keyword w
	int addr_s_file; // the address of the node in search array which is for keyword w that contain file f
	int addr_s_prev_file; // the address of the node in search array which is for keyword w that contain previous file f_-1
	int addr_s_next_file; // the address of the node in search array which is for keyword w that contain next file f_+1
	int keyword_hash;
	int r_p; // r'
};

struct del_table // Td, for each file, 4 bytes
{
	int addr_d_D_first;
};

/* auxiliary structure */
struct index_keyword // the index of a keyword and files id
{
	string keyword;
	string *id;
	int number; // numbers of file for a keyword w

	void build_id()
	{
		id = new string[this->number];
	}

	void del_id()
	{
		delete[] id;
	}
};

struct index_file // the index of a file and keywords
{
	string id;
	string keyqord[3];
	int number; // numbers of keyword for a file f
};
/* auxiliary structure */

/* auxiliary function */
inline void string_to_byte(byte *b_text, string s_text, int b_text_len)
{
	memcpy((char*)b_text, s_text.c_str(), b_text_len);
}

void random_location(int *location_ptr, int range, int number) // 產生一個大小為number的隨機數列，範圍從0到range-1，數字不會重複
{
	if (number > range)
	{
		cout << "Error: number cannot greater than range" << endl;
		return;
	}

	int *used = new int[number];
	memset(used, 0, number*sizeof(int));

	int counter = 0;
	while (1)
	{
		int temp = rand() % range;

		if (used[temp] == 0)
		{
			cout << temp << endl;
			used[temp] = 1;
			location_ptr[counter] = temp;
			counter++;
		}
		
		if (counter == number)
			break;
	}
	delete[] used;
}
/* auxiliary function */

class DSSE
{
	public:
		void client_keygen()
		{
			memset(k1, 0x00, sizeof(k1));
			memset(k2, 0x01, sizeof(k2));
			memset(k3, 0x02, sizeof(k3));
			memset(k4, 0x03, sizeof(k4));
		}

		void client_index_build()
		{
			/* build index for keyword 
			keyword_set[0].keyword = "w1";
			keyword_set[1].keyword = "w2";
			keyword_set[2].keyword = "w3";

			keyword_set[0].id[0] = "f1";
			keyword_set[0].id[1] = "f2";
			keyword_set[0].id[2] = "f3";
			keyword_set[0].number = 3;

			keyword_set[1].id[0] = "f2";
			keyword_set[1].number = 1;

			keyword_set[2].id[0] = "f2";
			keyword_set[2].id[1] = "f3";
			keyword_set[2].number = 2;
			 build index for keyword */

			/* build index for keyword  */
			DIR *dp;
			fstream file_obj;

			dp = opendir("./Index");
			struct dirent *ep;

			string path;
			if (dp != NULL)
			{
				int keyword_number = 0, file_number = 0, start, end;
				int length;
				char *buf = NULL;

				while (ep = readdir(dp)) // read the index file, the index file need to be UNIX format
				{
					//printf("%s\n", ep->d_name);
					keyword_number++;
				}
				keyword_number = keyword_number - 2; // 扣掉當前目錄和上層目錄
				cout << "We have " << keyword_number << " keywords" << endl;
				keyword_set = new struct index_keyword[keyword_number];
				rewinddir(dp);
				readdir(dp);
				readdir(dp);

				int counter = 0;
				while (ep = readdir(dp))
				{
					file_number = 0;
					printf("%s\n", ep->d_name);
					keyword_set[counter].keyword = ep->d_name; // write keyword to keyword_set
					path.clear();
					path = "./Index/" + path.assign(ep->d_name);
					file_obj.open(path, ios::in | ios::binary);

					if (!file_obj)
					{
						cerr << "Index file: " << ep->d_name << " open failed..." << endl << endl;
						continue;
					}

					/* Calculate file size (bytes) */
					file_obj.seekg(0, ios::end);
					length = file_obj.tellg(); // the size of the file
					file_obj.seekg(0, ios::beg);
					cout << "Index file: " << ep->d_name << " is " << length << " bytes." << endl;
					/* Calculate file size (bytes) */

					buf = new char[length];
					file_obj.read(buf, length);

					/* Counte the number of file */
					for (int i = 0; i < length; i++)
					{
						if (buf[i] == '\n')
						{
							file_number++;
						}
					}
					cout << "File number: " << file_number << endl;
					/* Counte the number of file */

					keyword_set[counter].number = file_number; // write numbers of file include a keyword
					keyword_set[counter].build_id(); // generate a space to store id

					start = 0;
					file_number = 0;
					for (int i = 0; i < length; i++)
					{
						if (buf[i] == '\n')
						{
							end = i;
							//cout << "DEBUG: start = " << start << endl;
							//cout << "DEBUG: end = " << end << endl;
							keyword_set[counter].id[file_number].assign(&buf[start], end - start); // write file id
							start = end + 1;
							file_number++;
						}
					}
					file_obj.close();
					delete[] buf;
					counter++;
				}
			}
			/* build index for keyword  */


			/* build index for file */
			file_set[0].id = "f1";
			file_set[1].id = "f2";
			file_set[2].id = "f3";

			file_set[0].keyqord[0] = "w1";
			file_set[0].number = 1;

			file_set[1].keyqord[0] = "w1";
			file_set[1].keyqord[1] = "w2";
			file_set[1].keyqord[2] = "w3";
			file_set[1].number = 3;

			file_set[2].keyqord[0] = "w1";
			file_set[2].keyqord[1] = "w3";
			file_set[2].number = 2;
			/* build index for file */
		}
		
		void client_enc()
		{
			/* For 32-bit random number r and r_p */
			random_device rd;
			default_random_engine eng{ rd() };
			uniform_int_distribution<> dist;
			/* For 32-bit random number r and r_p */

			/* Initialization */
			memset(As, -1, sizeof(As));
			memset(Ad, -1, sizeof(Ad));
			memset(Ts, -1, sizeof(Ts));
			memset(Td, -1, sizeof(Td));
			/* Initialization */

			int keyeord_number = 3;
			int file_number = 3;

			int node_number = 0;
			for (int i = 0; i < keyeord_number; i++)
			{
				node_number = node_number + keyword_set[i].number;
			}

			string file_id_string; // to store sha256(file_name) temporarily

			/* Generate a sequence to store node N at random location in As */
			int *As_index = new int[ARRAY_SIZE + FREE_SIZE];
			random_location(As_index, ARRAY_SIZE + FREE_SIZE, ARRAY_SIZE + FREE_SIZE);
			/* Generate a sequence to store node N at random location in As */
			
			/* Build As */
			int counter = 0;
			for (int i = 0; i < keyeord_number; i++) // for keyword, w1, w2, w3
			{
				Ts[F(k1, sizeof(k1), keyword_set[i].keyword, 2, 0)].addr_s_N_first = As_index[counter]; // build first element of Ts
				cout << "DEBUG: F(" << keyword_set[i].keyword << ") = " << F(k1, sizeof(k1), keyword_set[i].keyword, 2, 0) << endl;
				for (int j = 0; j < keyword_set[i].number; j++) // for file include the keyword
				{
					string_to_byte((byte*)As[As_index[counter]].id, sha256(keyword_set[i].id[j]), 32); // store ID to As
					//As[As_index[counter]].id = keyword_set[i].id[j];
					As[As_index[counter]].r = dist(eng); // generate r

					if (j == keyword_set[i].number - 1) // the last node for a keyword
					{
						As[As_index[counter]].addr_s_next = -1; // let array_index < 0 as NULL
					}
					else
					{
						As[As_index[counter]].addr_s_next = As_index[counter + 1];
					}
					counter++;
				}
			}
			cout << endl;
			/* Build As */

			/* Generate a sequence to store node N at random location in Ad */
			int *Ad_index = new int[ARRAY_SIZE + FREE_SIZE];
			random_location(Ad_index, ARRAY_SIZE + FREE_SIZE, ARRAY_SIZE + FREE_SIZE);
			/* Generate a sequence to store node N at random location in Ad */
			
			int keyword_hash;
			int file_hash;
			int temp_As_index;
			int temp_Ad_index;
			int temp_Ad_index2;

			counter = 0;
			for (int i = 0; i < file_number; i++) // for file id, f1, f2, f3
			{
				file_hash = F(k1, sizeof(k1), sha256(file_set[i].id), 2, 0);
				cout << "DEBUG: F(" << file_set[i].id << ") = " << file_hash << endl;
				Td[file_hash].addr_d_D_first = Ad_index[counter];
				
				for (int j = 0; j < file_set[i].number; j++) // for keyword in each file
				{
					keyword_hash = F(k1, sizeof(k1), file_set[i].keyqord[j], 2, 0);
					Ad[Ad_index[counter]].r_p = dist(eng);

					/* Addr_d(D_i+1) */
					if (j == file_set[i].number - 1) // the last node for a file
					{
						Ad[Ad_index[counter]].addr_d_next = -1;
					}
					else
					{
						Ad[Ad_index[counter]].addr_d_next = Ad_index[counter + 1];
					}
					/* Addr_d(D_i+1) */

					/* F(w) */
					Ad[Ad_index[counter]].keyword_hash = keyword_hash;
					/* F(w) */

					/* addr_s(N) */
					temp_As_index = Ts[keyword_hash].addr_s_N_first;
					while (1)
					{
						file_id_string = sha256(file_set[i].id);
						if (strncmp(As[temp_As_index].id, file_id_string.c_str(), 32) == 0)
						//if (As[temp_As_index].id == file_set[i].id)
						{
							Ad[Ad_index[counter]].addr_s_file = temp_As_index;
							break;
						}
						else
						{
							temp_As_index = As[temp_As_index].addr_s_next;
						}
					}
					/* addr_s(N) */

					/* addr_s(N+1) */
					Ad[Ad_index[counter]].addr_s_next_file = As[Ad[Ad_index[counter]].addr_s_file].addr_s_next;
					/* addr_s(N+1) */

					/* addr_s(N-1) */
					if (strncmp(As[Ts[keyword_hash].addr_s_N_first].id, file_id_string.c_str(), 32) == 0) // if we can find it Ts, there is no previous node
					//if (As[Ts[keyword_hash].addr_s_N_first].id == file_set[i].id)
					{
						Ad[Ad_index[counter]].addr_s_prev_file = -1;
					}
					else
					{
						if (i - 1 >= 0)
						{
							temp_As_index = Ts[keyword_hash].addr_s_N_first;
							while (1)
							{
								file_id_string = sha256(file_set[i - 1].id);
								if (strncmp(As[temp_As_index].id, file_id_string.c_str(), 32) == 0)
								//if (As[temp_As_index].id == file_set[i - 1].id)
								{
									Ad[Ad_index[counter]].addr_s_prev_file = temp_As_index;
									break;
								}
								else
								{
									temp_As_index = As[temp_As_index].addr_s_next;
								}
							}
						}
						else
						{
							Ad[Ad_index[counter]].addr_s_prev_file = -1;
						}
					}
					/* addr_s(N-1) */
					counter++;
				}
			}
			cout << endl;			

			/* build second element of Ts */
			
			for (int i = 0; i < keyeord_number; i++) // for each keyword
			{
				keyword_hash = F(k1, sizeof(k1), keyword_set[i].keyword, 2, 0);
				temp_As_index = Ts[keyword_hash].addr_s_N_first;
				file_id_string.clear();
				file_id_string.assign(As[temp_As_index].id, 32);
				temp_Ad_index = Td[F(k1, sizeof(k1), file_id_string, 2, 0)].addr_d_D_first;
				while (1)
				{
					if (Ad[temp_Ad_index].addr_s_file == temp_As_index)
					{
						Ts[keyword_hash].addr_d_N_first_dual = temp_Ad_index;
						break;
					}
					else
					{
						temp_Ad_index = Ad[temp_Ad_index].addr_d_next;
					}
				}
			}
			/* build second element of Ts */

			/* build addr_d(N+1) */
			for (int i = 0; i < file_number; i++)
			{
				file_id_string = sha256(file_set[i].id);
				file_hash = F(k1, sizeof(k1), file_id_string, 2, 0);
				temp_Ad_index = Td[file_hash].addr_d_D_first;
				while (1)
				{
					if (Ad[temp_Ad_index].addr_s_next_file != -1)
					{
						temp_As_index = Ad[temp_Ad_index].addr_s_next_file;
						file_id_string.clear();
						file_id_string.assign(As[temp_As_index].id, 32);
						temp_Ad_index2 = Td[F(k1, sizeof(k1), file_id_string, 2, 0)].addr_d_D_first;
						while (1)
						{
							if (Ad[temp_Ad_index2].addr_s_file == Ad[temp_Ad_index].addr_s_next_file)
							{
								Ad[temp_Ad_index].addr_d_next_file = temp_Ad_index2;
								break;
							}
							else
							{
								temp_Ad_index2 = Ad[temp_Ad_index2].addr_d_next;
							}
						}
					}
					else
					{
						Ad[temp_Ad_index].addr_d_next_file = -1;
					}

					if (Ad[temp_Ad_index].addr_d_next == -1)
					{
						break;
					}
					else
					{
						temp_Ad_index = Ad[temp_Ad_index].addr_d_next;
					}
				}
			}
			/* build addr_d(N+1) */

			/* build addr_d(N-1) */
			for (int i = 0; i < file_number; i++)
			{
				file_id_string = sha256(file_set[i].id);
				file_hash = F(k1, sizeof(k1), file_id_string, 2, 0);
				temp_Ad_index = Td[file_hash].addr_d_D_first;
				while (1)
				{
					if (Ad[temp_Ad_index].addr_s_prev_file != -1)
					{
						temp_As_index = Ad[temp_Ad_index].addr_s_prev_file;
						file_id_string.clear();
						file_id_string.assign(As[temp_As_index].id, 32);
						temp_Ad_index2 = Td[F(k1, sizeof(k1), file_id_string, 2, 0)].addr_d_D_first;
						while (1)
						{
							if (Ad[temp_Ad_index2].addr_s_file == Ad[temp_Ad_index].addr_s_prev_file)
							{
								Ad[temp_Ad_index].addr_d_prev_file = temp_Ad_index2;
								break;
							}
							else
							{
								temp_Ad_index2 = Ad[temp_Ad_index2].addr_d_next;
							}
						}
					}
					else
					{
						Ad[temp_Ad_index].addr_d_prev_file = -1;
					}

					if (Ad[temp_Ad_index].addr_d_next == -1)
					{
						break;
					}
					else
					{
						temp_Ad_index = Ad[temp_Ad_index].addr_d_next;
					}
				}
			}
			/* build addr_d(N-1) */
			cout << "Search index build complete" << endl;
			
			/* For free As */
			cout << "DEBUG: F(" << FREE << ") = " << F(k1, sizeof(k1), FREE, 2, 0) << endl;
			Ts[F(k1, sizeof(k1), FREE, 2, 0)].addr_s_N_first = As_index[ARRAY_SIZE + FREE_SIZE - 1];
			for (int i = ARRAY_SIZE + FREE_SIZE - 1; i >= ARRAY_SIZE; i--)
			{
				memset(As[As_index[i]].id, -1, 32);
				//As[As_index[i]].id = "-1";
				
				if (i == ARRAY_SIZE)
					As[As_index[i]].addr_s_next = -1;
				else
					As[As_index[i]].addr_s_next = As_index[i - 1];
					
				As[As_index[i]].r = Ad_index[i];
			}
			/* For free As */
			cout << "Free index build complete" << endl;

			/* Write random string to remaining As and Ad */
			for (int i = counter; i < ARRAY_SIZE; i++)
			{
				As[As_index[counter]].addr_s_next = dist(eng);
				As[As_index[counter]].r = dist(eng);
				for (int j = 0; j < 8; j++)
				{
					*((int*)As[As_index[counter]].id + j) = dist(eng); // write 32 bytes random string to As.id[]
				}

				Ad[Ad_index[counter]].addr_d_next = dist(eng);
				Ad[Ad_index[counter]].addr_d_next_file = dist(eng);
				Ad[Ad_index[counter]].addr_d_prev_file = dist(eng);
				Ad[Ad_index[counter]].addr_s_file = dist(eng);
				Ad[Ad_index[counter]].addr_s_next_file = dist(eng);
				Ad[Ad_index[counter]].addr_s_prev_file = dist(eng);
				Ad[Ad_index[counter]].keyword_hash = dist(eng);
				Ad[Ad_index[counter]].r_p = dist(eng);
			}
			cout << "Random data write complete" << endl;
			/* Write random string to remaining As and Ad */
			
			/* Encryption As */
			char *temp_ptr;
			string Kw, H1;
			for (int i = 0; i < keyeord_number; i++)
			{
				Kw = CMAC_AES_128(k3, sizeof(k3), keyword_set[i].keyword); // fora keyword, generate a key for HMAC_SHA_256
				temp_As_index = Ts[F(k1, sizeof(k1), keyword_set[i].keyword, 2, 0)].addr_s_N_first;
				while (temp_As_index != -1)
				{
					H1 = HMAC_SHA_256((byte*)Kw.c_str(), Kw.size(), to_string(As[temp_As_index].r)); // generate a 256-bit key
					H1 = H1.append(H1.c_str(), 4); // to increase key length to 36 bytes
					temp_ptr = (char*)&As[temp_As_index];
					temp_As_index = As[temp_As_index].addr_s_next;
					for (int j = 0; j < 36; j++)
					{
						temp_ptr[j] = temp_ptr[j] ^ H1.c_str()[j];
					}
				}
			}
			/* Encryption As */

			/* Encryption Ad */
			string Kf, H2;
			for (int i = 0; i < file_number; i++)
			{
				Kf = CMAC_AES_128(k3, sizeof(k3), sha256(file_set[i].id));
				temp_Ad_index = Td[F(k1, sizeof(k1), sha256(file_set[i].id), 2, 0)].addr_d_D_first;
				while (temp_Ad_index != -1)
				{
					H2 = HMAC_SHA_256((byte*)Kf.c_str(), Kf.size(), to_string(Ad[temp_Ad_index].r_p));
					temp_ptr = (char*)&Ad[temp_Ad_index];
					temp_Ad_index = Ad[temp_Ad_index].addr_d_next;
					for (int j = 0; j < 28; j++)
					{
						temp_ptr[j] = temp_ptr[j] ^ H2.c_str()[j];
					}
				}
			}
			/* Encryption Ad */

			/* Encryption  Ts */
			string G_k2_w;
			for (int i = 0; i < keyeord_number; i++) // for each keyword
			{
				G_k2_w = CMAC_AES_128(k2, sizeof(k2), keyword_set[i].keyword);
				temp_ptr = (char*)&Ts[F(k1, sizeof(k1), keyword_set[i].keyword, 2, 0)];
				for (int j = 0; j < sizeof(struct search_table); j++)
				{
					temp_ptr[j] = temp_ptr[j] ^ G_k2_w.c_str()[j];
				}
			}
			/* Encryption  Ts */

			/* Encryption Td */
			string G_k2_f;
			for (int i = 0; i < file_number; i++) // for each keyword
			{
				G_k2_f = CMAC_AES_128(k2, sizeof(k2), sha256(file_set[i].id));
				temp_ptr = (char*)&Td[F(k1, sizeof(k1), sha256(file_set[i].id), 2, 0)];
				for (int j = 0; j < sizeof(struct del_table); j++)
				{
					temp_ptr[j] = temp_ptr[j] ^ G_k2_f.c_str()[j];
				}
			}
			/* Encryption Td */

			delete[] As_index;
			delete[] Ad_index;

			fstream enc_dest;
			string path;
			/* Write Ts to server */
			for (int i = 0; i < keyeord_number; i++)
			{
				keyword_hash = F(k1, sizeof(k1), keyword_set[i].keyword, 2, 0);
				path = "./EncData/Ts_" + to_string(keyword_hash) + ".enc";
				cout << "Create file: " << path << endl;
				enc_dest.open(path, ios::out | ios::binary);
				if (!enc_dest)
					cerr << "Destination file create failed." << endl << endl;
				enc_dest.write((char*)&Ts[keyword_hash], sizeof(Ts[keyword_hash]));
				enc_dest.close();
			}

			// for free As index, Ts
			keyword_hash = F(k1, sizeof(k1), FREE, 2, 0);
			path = "./EncData/Ts_Free";
			cout << "Create file: " << path << endl;
			enc_dest.open(path, ios::out | ios::binary);
			if (!enc_dest)
				cerr << "Destination file create failed." << endl << endl;
			enc_dest.write((char*)&Ts[keyword_hash], sizeof(Ts[keyword_hash]));
			enc_dest.close();
			cout << endl;
			/* Write Ts to server */

			/* Write Td to server */
			for (int i = 0; i < file_number; i++)
			{
				file_hash = F(k1, sizeof(k1), sha256(file_set[i].id), 2, 0);
				path = "./EncData/Td_" + to_string(file_hash) + ".enc";
				cout << "Create file: " << path << endl;
				enc_dest.open(path, ios::out | ios::binary);
				if (!enc_dest)
					cerr << "Destination file create failed." << endl << endl;
				enc_dest.write((char*)&Td[file_hash], sizeof(Td[file_hash]));
				enc_dest.close();
			}
			cout << endl;
			/* Write Td to server */

			/* Write As to server */
			for (int i = 0; i < ARRAY_SIZE + FREE_SIZE; i++)
			{
				path = "./EncData/As_" + to_string(i) + ".enc";
				cout << "Create file: " << path << endl;
				enc_dest.open(path, ios::out | ios::binary);
				if (!enc_dest)
					cerr << "Destination file create failed." << endl << endl;
				enc_dest.write((char*)&As[i], sizeof(As[i]));
				enc_dest.close();
			}
			/* Write As to server */

			/* Write Ad to server */
			for (int i = 0; i < ARRAY_SIZE + FREE_SIZE; i++)
			{
				path = "./EncData/Ad_" + to_string(i) + ".enc";
				cout << "Create file: " << path << endl;
				enc_dest.open(path, ios::out | ios::binary);
				if (!enc_dest)
					cerr << "Destination file create failed." << endl << endl;
				enc_dest.write((char*)&Ad[i], sizeof(Ad[i]));
				enc_dest.close();
			}
			/* Write Ad to server */
		}

		void client_srch_token(string keyword, int *F_k1_w, string *G_k2_w, string *P_k3_w)
		{
			*F_k1_w = F(k1, sizeof(k1), keyword, 2, 0);
			*G_k2_w = CMAC_AES_128(k2, sizeof(k2), keyword);
			*P_k3_w = CMAC_AES_128(k3, sizeof(k3), keyword);
		}

		void server_search(int F_k1_w, string G_k2_w, string P_k3_w)
		{
			struct search_table temp_Ts;
			struct search_array temp_As;
			char *temp_ptr;
			string H1;
			string sha256_id, id_encoded;

			fstream enc_src;
			string path = "./EncData/Ts_" + to_string(F_k1_w) + ".enc";
			cout << "Open file: " << path << endl;
			enc_src.open(path, ios::in | ios::binary);
			if (!enc_src)
				cerr << "No such file." << endl << endl;
			else
			{
				enc_src.read((char*)&temp_Ts, sizeof(temp_Ts));
				enc_src.close();
				temp_ptr =(char*)&temp_Ts;
				
				for (int i = 0; i < sizeof(temp_Ts); i++)
				{
					temp_ptr[i] = temp_ptr[i] ^ G_k2_w.c_str()[i]; // decryption Ts
				}
				
				path = "./EncData/As_" + to_string(temp_Ts.addr_s_N_first) + ".enc";
				cout << "Open file: " << path << endl;
				enc_src.open(path, ios::in | ios::binary);
				if (!enc_src)
					cerr << "No such file." << endl << endl;
				else
				{
					enc_src.read((char*)&temp_As, sizeof(temp_As));
					enc_src.close();
					temp_ptr = (char*)&temp_As;
					H1 = HMAC_SHA_256((byte*)P_k3_w.c_str(), P_k3_w.size(), to_string(temp_As.r)); // calculate a 256-bit key
					H1 = H1.append(H1.c_str(), 4); // to increase key length to 36 bytes
					for (int i = 0; i < 36; i++)
					{
						temp_ptr[i] = temp_ptr[i] ^ H1.c_str()[i];
					}
					sha256_id.assign(temp_As.id, 32);
					id_encoded = hex_encoder(sha256_id);// to show the hex data in the command line
					cout << "Return file ID: " << id_encoded << endl;
					while (temp_As.addr_s_next != -1)
					{
						path = "./EncData/As_" + to_string(temp_As.addr_s_next) + ".enc";
						cout << "Open file: " << path << endl;
						enc_src.open(path, ios::in | ios::binary);
						if (!enc_src)
						{
							cerr << "No such file." << endl << endl;
							break;
						}
						else
						{
							enc_src.read((char*)&temp_As, sizeof(temp_As));
							enc_src.close();
							temp_ptr = (char*)&temp_As;
							H1 = HMAC_SHA_256((byte*)P_k3_w.c_str(), P_k3_w.size(), to_string(temp_As.r)); // calculate a 256-bit key
							H1 = H1.append(H1.c_str(), 4); // to increase key length to 36 bytes
							for (int i = 0; i < 36; i++)
							{
								temp_ptr[i] = temp_ptr[i] ^ H1.c_str()[i];
							}
							sha256_id.assign(temp_As.id, 32);
							id_encoded = hex_encoder(sha256_id);// to show the hex data in the command line
							cout << "Return file ID: " << id_encoded << endl;
						}
					}
				}
			}
		}

		string client_add_token(string file_name) // return the numbers of keyword are included in a new file
		{
			/* For 32-bit random number r and r_p */
			random_device rd;
			default_random_engine eng{ rd() };
			uniform_int_distribution<> dist;
			/* For 32-bit random number r and r_p */

			fstream token_file;
			string path;

			static int counter = 0;
			string keyword;

			int F_k1_w, F_k1_f;
			string G_k2_w, G_k2_f, P_k3_w, P_k3_f, H1, H2;
			struct search_array As;
			struct del_array Ad;
			string file_name_hash = sha256(file_name); // ID
			char *ptr = NULL;

			F_k1_f = F(k1, sizeof(k1), file_name_hash, 2, 0);
			G_k2_f = CMAC_AES_128(k2, sizeof(k2), file_name_hash);
			P_k3_f = CMAC_AES_128(k3, sizeof(k3), file_name_hash);

			path = "./AddToken/Pi_" + to_string(counter);
			
			token_file.open(path, ios::out | ios::binary);
			token_file.write((char*)&F_k1_f, sizeof(F_k1_f));
			token_file.write(G_k2_f.c_str(), G_k2_f.size());

			while (1)
			{
				cout << "Please enter the keyword in this file, enter \"EXIT\" to finish: " << endl << ">>";
				cin >> keyword;
				if (keyword == "EXIT")
				{
					break;
					token_file.close();
				}

				F_k1_w = F(k1, sizeof(k1), keyword, 2, 0);
				G_k2_w = CMAC_AES_128(k2, sizeof(k2), keyword);
				P_k3_w = CMAC_AES_128(k3, sizeof(k3), keyword);

				As.r = dist(eng);
				Ad.r_p = dist(eng);

				H1 = HMAC_SHA_256((byte*)P_k3_w.c_str(), P_k3_w.size(), to_string(As.r)); // generate a 256-bit key
				H1 = H1.append(H1.c_str(), 4); // to increase key length to 36 bytes
				H2 = HMAC_SHA_256((byte*)P_k3_f.c_str(), P_k3_f.size(), to_string(Ad.r_p));

				string_to_byte((byte*)As.id, file_name_hash, 32); // store ID to As
				As.addr_s_next = 0;

				Ad.keyword_hash = F_k1_w;
				Ad.addr_d_next = Ad.addr_d_next_file = Ad.addr_d_prev_file = Ad.addr_s_file = Ad.addr_s_next_file = Ad.addr_s_prev_file = 0;

				ptr = (char*)&As;
				for (int i = 0; i < 36; i++) // encryption As
				{
					ptr[i] = ptr[i] ^ H1.c_str()[i];
				}

				ptr = (char*)&Ad;
				for (int i = 0; i < 28; i++) // encryption Ad
				{
					ptr[i] = ptr[i] ^ H2.c_str()[i];
				}
				
				token_file.write((char*)&F_k1_w, sizeof(F_k1_w));
				token_file.write(G_k2_w.c_str(), G_k2_w.size());
				token_file.write((char*)&As, sizeof(As));
				token_file.write((char*)&Ad, sizeof(Ad));
			}

			token_file.close();
			cout << "Create a add token file: " << path << endl;
			counter++;

			return path;
		}

		void server_add(string path)
		{
			fstream token_file, Td_file, Ts_file, As_file, Ad_file, next_As_file;
			string Td_path, Ts_path, As_path, Ad_path;
			char *ptr1 = NULL, *ptr2 = NULL;

			int F_k1_w, F_k1_f;
			char buf[16];
			string G_k2_w, G_k2_f;
			struct search_array As, free_As, As_buf, next_As;
			struct del_array Ad, Ad_buf, token_Ad;
			struct search_table Ts, free_Ts;
			struct del_table Td;
			int new_N_first, new_N_first_dual;

			token_file.open(path, ios::in | ios::binary);
			if (!token_file)
			{
				cerr << "Error: cannot open token file: " << path << endl;
			}
			else
			{
				cout << "Open a add token file: " << path << endl;
				
				/* Get token file size */
				token_file.seekg(0, token_file.end);
				int length = token_file.tellg();
				token_file.seekg(0, token_file.beg);
				cout << "Token file size: " << length << " bytes" << endl;
				/* Get token file size */

				token_file.read((char*)&F_k1_f, sizeof(F_k1_f));
				token_file.read(buf, sizeof(buf));
				G_k2_f.assign(buf, sizeof(buf));
				Td_path = "./EncData/Td_" + to_string(F_k1_f) + ".enc";
				cout << "Create a new Td file: " << Td_path << endl;
				Td_file.open(Td_path, ios::out | ios::binary);
				if (!Td_file)
				{
					cerr << "Error: create Td file failed." << endl;
					return;
				}
				
				while ((int)token_file.tellg() != length)
				{
					memset(&Ad_buf, 0, sizeof(Ad_buf));

					token_file.read((char*)&F_k1_w, sizeof(F_k1_w));
					token_file.read(buf, sizeof(buf));
					G_k2_w.assign(buf, sizeof(buf));
					token_file.read((char*)&As, sizeof(As));
					token_file.read((char*)&token_Ad, sizeof(token_Ad));

					cout << "Search free As" << endl;
					Ts_path = "./EncData/Ts_Free"; // Open Ts_Free
					Ts_file.open(Ts_path, ios::in | ios::out | ios::binary);
					if (!Ts_file)
					{
						cerr << "Error: open file: " << Ts_path << " failed." << endl;
					}
					else
					{
						cout << "Open free As index file: " << Ts_path << endl;
						Ts_file.read((char*)&free_Ts, sizeof(free_Ts));
						Ts_file.seekg(0, Ts_file.beg);

						cout << "Free As index: " << free_Ts.addr_s_N_first << endl;

						As_path = "./EncData/As_" + to_string(free_Ts.addr_s_N_first) + ".enc"; // Open free As
						As_file.open(As_path, ios::in | ios::out | ios::binary);
						if (!As_file)
						{
							cerr << "Error: Open file: " << As_path << " failed." << endl;
						}
						else
						{
							cout << "Open free As file: " << As_path << endl;
							As_file.read((char*)&free_As, sizeof(free_As));
							As_file.seekg(0, As_file.beg);
							cout << "The corresponding Ad index: " << free_As.r << endl;
							if (free_As.addr_s_next == -1)
								cout << "As already is full!" << endl;
							else
								cout << "Next free As index: " << free_As.addr_s_next << endl; // Phi_prev
							
							new_N_first_dual = free_As.r; // Phi*
							new_N_first = free_Ts.addr_s_N_first; // Phi
							Ad_buf.addr_s_prev_file = new_N_first; // prepare Ad_buf for update dual of As
							Ad_buf.addr_d_prev_file = new_N_first_dual;

							free_Ts.addr_s_N_first = free_As.addr_s_next;
							Ts_file.write((char*)&free_Ts, sizeof(free_Ts)); // update search table Ts for free
							Ts_file.close();
							
							/* Update Ad */
							Ts_path = "EncData/Ts_" + to_string(F_k1_w) +".enc"; // open Ts for a keywoord
							Ts_file.open(Ts_path, ios::in | ios::out | ios::binary);
							if (!Ts_file)
							{
								cerr << "Error: open file: " << Ts_path << " failed." << endl;
							}
							else
							{
								cout << "Open As index file for some keyword: " << Ts_path << endl;
								Ts_file.read((char*)&Ts, sizeof(Ts));
								Ts_file.seekg(0, Ts_file.beg);
								ptr1 = (char*)&Ts;
								for (int i = 0; i < sizeof(Ts); i++) // decryption Ts
								{
									ptr1[i] = ptr1[i] ^ G_k2_w.c_str()[i];
								}
								cout << "Next As index for some keyword: " << Ts.addr_s_N_first << endl; // Alpha
								cout << "Dual Ad index for some keyword: " << Ts.addr_d_N_first_dual << endl; // Alpha*

								Ad_path = "./EncData/Ad_" + to_string(Ts.addr_d_N_first_dual);
								cout << "Open dual Ad file: " << path << endl;
								Ad_file.open(Ad_path, ios::in | ios::out | ios::binary);
								if (!Ad_file)
								{
									cerr << "Error: open file: " << Ad_path << " failed." << endl;
								}
								else
								{
									Ad_file.read((char*)&Ad, sizeof(Ad));
									Ad_file.seekg(0, Ad_file.beg);
									ptr1 = (char*)&Ad;
									ptr2 = (char*)&Ad_buf;
									for (int i = 0; i < sizeof(Ad); i++) // for reserve H2
									{
										ptr1[i] = ptr1[i] ^ ptr2[i];
									}
									Ad_file.write((char*)&Ad, sizeof(Ad)); // update Ad[Alpha*]
									Ad_file.close();
								}
								
								memset(&Ad_buf, 0, sizeof(Ad_buf));

								As_path = "./EncData/As_" + to_string(free_As.addr_s_next) + ".enc";
								next_As_file.open(As_path, ios::in | ios::binary);
								if (!next_As_file)
								{
									cerr << "Error: open file: " << As_path << " failed." << endl;
								}
								else
								{
									next_As_file.read((char*)&next_As, sizeof(next_As));
									next_As_file.close();
									
									if ((int)token_file.tellg() == length)
										Ad_buf.addr_d_next = -1; // Phi*_prev
									else
										Ad_buf.addr_d_next = next_As.r; // Phi*_prev
									
									Ad_buf.addr_d_next_file = Ts.addr_d_N_first_dual;
									Ad_buf.addr_s_file = Ts.addr_d_N_first_dual;
									Ad_buf.addr_s_next_file = Ts.addr_s_N_first;

									Ad_path = "./EncData/Ad_" + to_string(new_N_first_dual);
									cout << "Open dual Ad file: " << path << endl;
									Ad_file.open(Ad_path, ios::in | ios::out | ios::binary);
									if (!Ad_file)
									{
										cerr << "Error: open file: " << Ad_path << " failed." << endl;
									}
									else
									{
										Ad_file.read((char*)&Ad, sizeof(Ad));
										Ad_file.seekg(0, Ad_file.beg);
										ptr1 = (char*)&Ad;
										ptr2 = (char*)&Ad_buf;

										for (int i = 0; i < sizeof(Ad); i++)
										{
											ptr1[i] = ptr1[i] ^ ptr2[i];
											Ad_file.write((char*)&Ad, sizeof(Ad));
											Ad_file.close();
										}
									}

								}
								/* Update Ad */

								/* Update Td */
								if ((int)token_file.tellg() == length)
								{
									Td.addr_d_D_first = new_N_first_dual;

									ptr1 = (char*)&Td;
									for (int i = 0; i < sizeof(Td); i++)
									{
										ptr1[i] = ptr1[i] ^ G_k2_f.c_str()[i];
									}
								}
								/* Update Td */

								ptr1 = (char*)&As;
								ptr2 = (char*)&As_buf;
								memset(ptr2, 0, sizeof(As_buf));
								As_buf.addr_s_next = Ts.addr_s_N_first;
								for (int i = 0; i < sizeof(As); i++) // for reverse H1
								{
									ptr1[i] = ptr1[i] ^ ptr2[i];
								}
								As_file.write(ptr1, sizeof(As));
								As_file.close();

								Ts.addr_s_N_first = new_N_first; // update the search table
								Ts.addr_d_N_first_dual = new_N_first_dual;
								
								ptr1 = (char*)&Ts;
								for (int i = 0; i < sizeof(Ts); i++) // re-encryption
								{
									ptr1[i] = ptr1[i] ^ G_k2_w.c_str()[i];
								}
								Ts_file.write((char*)&Ts, sizeof(Ts));
								Ts_file.close();
							}
						}
					}
				}
				Td_file.close();
				token_file.close();
			}
		}

		void client_del_token(string file_name, int *F_k1_f, string *G_k2_f, string *P_k3_f, string *sha256_id)
		{
			*sha256_id = sha256(file_name);
			*F_k1_f = F(k1, sizeof(k1), *sha256_id, 2, 0);
			*G_k2_f = CMAC_AES_128(k2, sizeof(k2), *sha256_id);
			*P_k3_f = CMAC_AES_128(k3, sizeof(k3), *sha256_id);
		}

		void server_del(int F_k1_f, string G_k2_f, string P_k3_f, string sha256_id)
		{
			fstream Td_file, Ad_file, As_file, Ts_file, Ad_temp_file;
			struct del_table Td;
			struct del_array Ad, Ad_temp, Ad_buf; // Ad_temp for Ad_prev and Ad_next
			struct search_array As, As_buf;
			struct search_table Ts, Ts_buf;
			string Td_path, Ad_path, As_path, Ts_path;
			char *ptr, *ptr_buf;
			string H2;
			int next_Ad = 0;

			/* For 32-bit random number r and r_p */
			random_device rd;
			default_random_engine eng{ rd() };
			uniform_int_distribution<> dist;
			/* For 32-bit random number r and r_p */

			Td_path = "./EncData/Td_" + to_string(F_k1_f) + ".enc";
			cout << "Open delete table file: " << Td_path << endl;
			Td_file.open(Td_path, ios::in | ios::binary);
			if (!Td_file)
			{
				cerr << "Error: Td file open faild..." << endl;
			}
			else
			{
				Td_file.read((char*)&Td, sizeof(Td));
				Td_file.close();
				
				ptr = (char*)&Td;
				for (int i = 0; i < sizeof(Td); i++) // decryption Td
				{
					ptr[i] = ptr[i] ^ G_k2_f.c_str()[i];
				}
				
				next_Ad = Td.addr_d_D_first;
				while (next_Ad != -1)
				{
					cout << "Ad_i index for some file: " << next_Ad << endl;
					Ad_path = "./EncData/Ad_" + to_string(next_Ad) + ".enc";
					cout << "Open delete array file: " << Ad_path << endl;
					Ad_file.open(Ad_path, ios::in | ios::out | ios::binary); // Open Ad_i
					if (!Ad_file)
						cerr << "Error: Ad file open faild..." << endl;
					else
					{
						Ad_file.read((char*)&Ad, sizeof(Ad)); // Read Ad_i to memory
						Ad_file.seekg(0, Ad_file.beg);

						H2 = HMAC_SHA_256((byte*)P_k3_f.c_str(), P_k3_f.size(), to_string(Ad.r_p));
						ptr = (char*)&Ad;
						for (int i = 0; i < 28; i++) // decryption Ad
						{
							ptr[i] = ptr[i] ^ H2.c_str()[i];
						}
						cout << "Next Ad_i+1 index                 : " << Ad.addr_d_next << endl;
						cout << "Previous Ad_-1 index for As_-1    : " << Ad.addr_d_prev_file << endl;
						cout << "Next Ad_+1 index for As_+1        : " << Ad.addr_d_next_file << endl;
						cout << "Dual As_i index                   : " << Ad.addr_s_file << endl;
						cout << "Dual As_-1 index for previous file: " << Ad.addr_s_prev_file << endl;
						cout << "Dual As_+1 index for next file    : " << Ad.addr_s_next_file << endl;
						cout << "Keyword hash: " << Ad.keyword_hash << endl;

						Ts_path = "./EncData/Ts_Free";
						Ts_file.open(Ts_path, ios::in | ios::out | ios::binary); // open Ts_Free for find the free As 
						if (!Ts_file)
							cerr << "Open " << Ts_path << " failed..." << endl;
						else
						{
							Ts_file.read((char*)&Ts, sizeof(Ts));
							Ts_file.seekg(0, Ts_file.beg);

							/* Free the corrsponding As_i */
							As_path = "./EncData/As_" + to_string(Ad.addr_s_file) + ".enc";
							As_file.open(As_path, ios::out | ios::binary);
							if (!As_file)
								cerr << "Error: open " << As_path << " failed..." << endl;
							else
							{
								cout << "Open As file: " << As_path << endl;
								memset(As.id, -1, 32);
								As.addr_s_next = Ts.addr_s_N_first; // point to next free As (the last free As originially)
								As.r = Td.addr_d_D_first; // for free As, it point to the dual free Ad
								As_file.write((char*)&As, sizeof(As));
								As_file.close();
								cout << "**** Free the file: " << As_path << " and point to the last free As originially As_" << Ts.addr_s_N_first << ".enc ****" << endl;
							}
							/* Free the corrsponding As_i */

							Ts.addr_s_N_first = Ad.addr_s_file; // update Ts_Free to point to new free As
							Ts_file.write((char*)&Ts, sizeof(Ts));
							Ts_file.close();
							cout << "**** Update the file: " << Ts_path << " to point to file: " << As_path <<" ****" << endl;
						}


						/* Update As_-1 */
						if (Ad.addr_s_prev_file == -1) // no previous As, so we need to update Ts[F(w)]
						{
							Ts_path = "./EncData/Ts_" + to_string(Ad.keyword_hash) + ".enc";
							cout << "No previous As_-1, modify seach table Ts!" << endl;
							cout << "Open file: " << Ts_path << endl;
							Ts_file.open(Ts_path, ios::in | ios::out | ios::binary);
							if (!Ts_file)
								cerr << "Error: open " << Ts_path << " failed..." << endl;
							else
							{
								Ts_file.read((char*)&Ts, sizeof(Ts));
								Ts_file.seekg(0, Ts_file.beg);
								memset(&Ts_buf, 0, sizeof(Ts_buf));
								Ts_buf.addr_s_N_first = Ad.addr_s_file ^ Ad.addr_s_next_file;
								Ts_buf.addr_d_N_first_dual = Td.addr_d_D_first ^ Ad.addr_d_next_file;
								ptr = (char*)&Ts;
								ptr_buf = (char*)&Ts_buf;
								for (int i = 0; i < sizeof(Ts); i++)
								{
									ptr[i] = ptr[i] ^ ptr_buf[i];
								}
								Ts_file.write((char*)&Ts, sizeof(Ts));
								Ts_file.close();
								cout << "**** Update the search table file: " << Ts_path << " ****" << endl;
								cout << "	Point to the first As file index: " << Ad.addr_s_next_file << endl;
								cout << "	Point to the dula Ad file index: " << Ad.addr_d_next_file << endl;
							}
						}
						else // update previous As_-1
						{
							As_path = "./EncData/As_" + to_string(Ad.addr_s_prev_file) + ".enc";
							cout << "Open previous As_-1 file : " << As_path << endl;
							As_file.open(As_path, ios::in | ios::out | ios::binary);
							if (!As_file)
								cerr << "Error: open " << As_path << " failed..." << endl;
							else
							{
								As_file.read((char*)&As, sizeof(As));
								As_file.seekg(0, As_file.beg);
								memset(&As_buf, 0, sizeof(As_buf));
								As_buf.addr_s_next = Ad.addr_s_file ^ Ad.addr_s_next_file;
								ptr = (char*)&As;
								ptr_buf = (char*)&As_buf;
								for (int i = 0; i < sizeof(As); i++)
								{
									ptr[i] = ptr[i] ^ ptr_buf[i];
								}
								As_file.write((char*)&As, sizeof(As));
								As_file.close();
								cout << "**** Update the search array file: " << As_path << " to point to As_" << Ad.addr_s_next_file << ".enc ****" << endl;
							}
						}
						/* Update As_-1 */


						/* Update Ad_-1 */
						if (Ad.addr_d_prev_file == -1) // no previous Ad_-1
						{
							cout << "No previous Ad_-1, DO NOTHING!" << endl; // donothing
						}
						else
						{
							Ad_path = "./EncData/Ad_" + to_string(Ad.addr_d_prev_file) + ".enc";
							cout << "Open previous Ad_-1 file: " << Ad_path << endl;
							Ad_temp_file.open(Ad_path, ios::in | ios::out | ios::binary);
							if (!Ad_temp_file)
								cerr << "Error: open " << Ad_path << " failed..." << endl;
							else
							{
								Ad_temp_file.read((char*)&Ad_temp, sizeof(Ad_temp));
								Ad_temp_file.seekg(0, Ad_temp_file.beg);
								memset(&Ad_buf, 0, sizeof(Ad_buf));
								Ad_buf.addr_d_next_file = Td.addr_d_D_first ^ Ad.addr_d_next_file;
								Ad_buf.addr_s_next_file = Ad.addr_s_file ^ Ad.addr_s_next_file;
								ptr = (char*)&Ad_temp;
								ptr_buf = (char*)&Ad_buf;
								for (int i = 0; i < sizeof(Ad_temp); i++)
								{
									ptr[i] = ptr[i] ^ ptr_buf[i];
								}
								Ad_temp_file.write((char*)&Ad_temp, sizeof(Ad_temp));
								Ad_temp_file.close();
								cout << "**** Update the delete array file: " << Ad_path << " : ****" << endl;
								cout << "	Next Ad for next file index: " << Ad.addr_d_next_file << endl;
								cout << "	Next As for next file index: " << Ad.addr_s_next_file << endl;
							}
						}
						/* Update Ad_-1 */


						/* Update Ad_+1 */
						if (Ad.addr_d_next_file == -1) // no next Ad_+1
						{
							cout << "No previous Ad_+1, DO NOTHING!" << endl; // donothing
						}
						else
						{
							Ad_path = "./EncData/Ad_" + to_string(Ad.addr_d_next_file) + ".enc";
							cout << "Open previous Ad_+1 file: " << Ad_path << endl;
							Ad_temp_file.open(Ad_path, ios::in | ios::out | ios::binary);
							if (!Ad_temp_file)
								cerr << "Error: open " << Ad_path << " failed..." << endl;
							else
							{
								Ad_temp_file.read((char*)&Ad_temp, sizeof(Ad_temp));
								Ad_temp_file.seekg(0, Ad_temp_file.beg);
								memset(&Ad_buf, 0, sizeof(Ad_buf));
								Ad_buf.addr_d_prev_file = Td.addr_d_D_first ^ Ad.addr_d_prev_file;
								Ad_buf.addr_s_prev_file = Ad.addr_s_file ^ Ad.addr_s_prev_file;
								ptr = (char*)&Ad_temp;
								ptr_buf = (char*)&Ad_buf;
								for (int i = 0; i < sizeof(Ad_temp); i++)
								{
									ptr[i] = ptr[i] ^ ptr_buf[i];
								}
								Ad_temp_file.write((char*)&Ad_temp, sizeof(Ad_temp));
								Ad_temp_file.close();
								cout << "**** Update the delete array file: " << Ad_path << " : ****" << endl;
								cout << "	Previous Ad for previous file index: " << Ad.addr_d_prev_file << endl;
								cout << "	Previous As for previous file index: " << Ad.addr_s_prev_file << endl;
							}
						}
						/* Update Ad_+1 */


						next_Ad = Ad.addr_d_next;
						/* Free D_i by filling with random string */
						Ad.addr_d_next = dist(eng);
						Ad.addr_d_next_file = dist(eng);
						Ad.addr_d_prev_file = dist(eng);
						Ad.addr_s_file = dist(eng);
						Ad.addr_s_next_file = dist(eng);
						Ad.addr_s_prev_file = dist(eng);
						Ad.keyword_hash = dist(eng);
						Ad.r_p = dist(eng);
						Ad_file.write((char*)&Ad, sizeof(Ad));
						Ad_file.close();
						cout << "**** Free D_i by filling with random string ****" << endl;
						/* Free D_i by filling with random string */
					}
					cout << "**** Process a couple As-Ad pairs ****" << endl;
				}
			}
			
			/* Delete Td[F_k1_f] */
			/* Delete Td[F_k1_f] */
		}
			
	private:
		byte k1[16], k2[16], k3[16], k4[16];
		
		struct index_keyword *keyword_set;
		struct index_file file_set[3];

		struct search_array As[ARRAY_SIZE + FREE_SIZE];
		struct del_array Ad[ARRAY_SIZE + FREE_SIZE];
		struct search_table Ts[SEARCH_TABLE_SIZE];
		struct del_table Td[DELETE_TABLE_SIZE];
};

int main()
{
	DSSE DSSE_obj;

	int F_k1_w; // search token
	string G_k2_w, P_k3_w; //search token
	string keyword, file_name;
	string add_token; // add token file path

	int F_k1_f; // selete tokwn
	string G_k2_f, P_k3_f; //delete token
	string sha256_id;
	
	int opcode;

	cout << endl << "Enter OP code:" << endl;
	cout << "	For client:" << endl;
	cout << "		0: Generate key" << endl;
	cout << "		1: Build keyword index" << endl;
	cout << "		2: Build search encrypted index" << endl;
	cout << "		3: Generate search token" << endl;
	cout << "		4: Generate add token" << endl;
	cout << "		5: Generate delete token" << endl;
	cout << "	For server:" << endl;
	cout << "		6: Keyword search" << endl;
	cout << "		7: Add a file" << endl;
	cout << "		8: Delete a file" << endl;
	cout << "	Ctrl + Z: Exit" << endl;
	cout << ">>";
	while (cin >> opcode)
	{
		switch (opcode)
		{
		case 0:
			DSSE_obj.client_keygen();
			cout << "Key generateion complete." << endl;
			break;

		case 1:
			DSSE_obj.client_index_build();
			cout << "Keyword building complete." << endl;
			break;

		case 2:
			DSSE_obj.client_enc();
			cout << "Search encrypted index building compllete." << endl;
			break;

		case 3:
			cout << "Enter a keyword you want to search: " << endl << ">>";
			cin >> keyword;
			DSSE_obj.client_srch_token(keyword, &F_k1_w, &G_k2_w, &P_k3_w);
			cout << "Generate a search token for keyword: " << keyword << endl;
			break;

		case 4:
			cout << "Enter the file name you want to add: " << endl << ">>";
			cin >> file_name;
			add_token = DSSE_obj.client_add_token(file_name);
			cout << "Generate a add token file for new file: " << file_name << endl;
			cout << "Add token file path: " << add_token << endl;
			break;

		case 5:
			cout << "Enter the file name you want to delete: " << endl << ">>";
			cin >> file_name;
			DSSE_obj.client_del_token(file_name, &F_k1_f, &G_k2_f, &P_k3_f, &sha256_id);
			cout << "Generate a delete token for file: " << file_name << endl;
			break;

		case 6:
			DSSE_obj.server_search(F_k1_w, G_k2_w, P_k3_w);
			break;

		case 7:
			DSSE_obj.server_add(add_token);
			break;

		case 8:
			DSSE_obj.server_del(F_k1_f, G_k2_f, P_k3_f, sha256_id);
			break;

		default:
			cout << "Opcode is incorrect..." << endl;
		}

		cout << endl << "Enter OP code:" << endl;
		cout << "	For client:" << endl;
		cout << "		0: Generate key" << endl;
		cout << "		1: Build keyword index" << endl;
		cout << "		2: Build search encrypted index" << endl;
		cout << "		3: Generate search token" << endl;
		cout << "		4: Generate add token" << endl;
		cout << "		5: Generate delete token" << endl;
		cout << "	For server:" << endl;
		cout << "		6: Keyword search" << endl;
		cout << "		7: Add a file" << endl;
		cout << "		8: Delete a file" << endl;
		cout << "	Ctrl + Z: Exit" << endl;
		cout << ">>";
	}

	return 0;
}