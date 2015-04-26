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

#define ARRAY_SIZE 7
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

	cout << "key: " << encoded << endl;
	cout << "plain text: " << plain << endl;

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

	cout << "cmac: " << encoded << endl;

	return mac;
}

int F(byte *user_key, int user_key_len, string keyword, int unit_bytes, int index) // hash function
{
	string cmac = CMAC_AES_128(user_key, user_key_len, keyword);
	byte temp[16];
	string_to_byte(temp, cmac, 16);
	unsigned short int *ptr_2byte;
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
			cout << endl;

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
					H1 = HMAC_SHA_256((byte*)Kw.c_str(), sizeof(Kw), to_string(As[temp_As_index].r)); // generate a 256-bit key
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
					H2 = HMAC_SHA_256((byte*)Kf.c_str(), sizeof(Kf), to_string(Ad[temp_Ad_index].r_p));
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

	DSSE_obj.client_keygen();
	DSSE_obj.client_index_build();
	DSSE_obj.client_enc();
	//DSSE_obj.search("w1");
	//DSSE_obj.search("w2");
	//DSSE_obj.search("w3");


	//DSSE_obj.add();
	//DSSE_obj.search("w1");
	



	return 0;
}