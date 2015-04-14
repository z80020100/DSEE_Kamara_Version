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

int F(string keyword) // simple keyword hash function
{
	if (keyword == "w1" || keyword == "f1")
	{
		return 0;
	}
	else if (keyword == "w2" || keyword == "f2")
	{
		return 1;
	}
	else if (keyword == "w3" || keyword == "f3")
	{
		return 2;
	}
	else if (keyword == "free")
	{
		return 3;
	}
	else
	{
		cout << "Error: keyword is not exist" << endl;
		exit(1);
	}
}

struct search_array //As, for each keyword
{
	string id; // the ID of the file
	struct search_array *addr_s_next; // the address of the next node in search array for a keyword
	byte r[16];
	struct del_array *free_Ad;
};

struct search_table // Ts, for each keyword
{
	struct search_array *addr_s_N_first; // the address of the first node in search array for a keyword
	struct search_array **addr_d_N_first_dual; // the address of the first node in deletion array whose fourth entry points to the first node in search array for a keyword
};

struct del_array // Ad, for each file
{
	struct del_array *addr_d_next; // the address of the next node in deletion array for a file f
	struct search_array **addr_d_prev_file; // the address of the fourth entry in deletion array which is points to the node for the next file f_+1 and keyword w
	struct search_array **addr_d_next_file; // the address of the fourth entry in deletion array which is points to the node for the previous file f_+1 and keyword w
	struct search_array *addr_s_file; // the address of the node in search array which is for keyword w that contain file f
	struct search_array *addr_s_prev_file; // the address of the node in search array which is for keyword w that contain previous file f_-1
	struct search_array *addr_s_next_file; // the address of the node in search array which is for keyword w that contain next file f_+1
	int keyword_hash;
	byte r_p[16]; // r'
};

struct del_table // Td, for each file
{
	struct del_array *addr_d_D_first;
};

struct index_keyword // the index of a keyword and files id
{
	string keyword;
	string id[3];
	int number; // numbers of file for a keyword w
};

struct index_file // the index of a file and keywords
{
	string id;
	string keyqord[3];
	int number; // numbers of keyword for a file f
};



class DSSE
{
	public:
		void keygen()
		{
			memset(k1, 0x00, sizeof(k1));
			memset(k2, 0x01, sizeof(k2));
			memset(k3, 0x02, sizeof(k3));
			memset(k4, 0x03, sizeof(k4));
		}

		void index_build()
		{
			/* build index for keyword */
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
			/* build index for keyword */


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
		
		void enc()
		{
			struct search_array As[8];
			struct del_array Ad[8];
			struct search_table Ts[4];
			struct del_table Td[3];
			
			int array_index;
			
			array_index = 0;
			for (int i = 0; i < 3; i++) // for keyword, w1, w2, w3
			{
				Ts[F(keyword_set[i].keyword)].addr_s_N_first = As + array_index; // build first element of Ts

				for (int j = 0; j < keyword_set[i].number; j++) // for file include the keyword
				{
					As[array_index].id = keyword_set[i].id[j];

					if (j == keyword_set[i].number - 1)
					{
						As[array_index].addr_s_next = NULL;
					}
					else
					{
						As[array_index].addr_s_next = As + array_index + 1;
					}
					array_index++;
				}
			}
			
			array_index = 0;
			int keyword_hash;
			struct search_array *temp_As;
			for (int i = 0; i < 3; i++) // for file id, f1, f2, f3 
			{
				Td[F(file_set[i].id)].addr_d_D_first = Ad + array_index;
				for (int j = 0; j < file_set[i].number; j++) // for keyword in each file
				{
					keyword_hash = F(file_set[i].keyqord[j]);

					/* Addr_d(D_i+1) */
					if (j == file_set[i].number - 1)
					{
						Ad[array_index].addr_d_next = NULL;
					}
					else
					{
						Ad[array_index].addr_d_next = Ad + array_index + 1;
					}
					/* Addr_d(D_i+1) */

					/* F(w) */
					Ad[array_index].keyword_hash = keyword_hash;
					/* F(w) */

					/* addr_s(N) */
					temp_As = Ts[keyword_hash].addr_s_N_first;
					while (1)
					{
						if (temp_As->id == file_set[i].id)
						{
							Ad[array_index].addr_s_file = temp_As;
							break;
						}
						else
						{
							temp_As = temp_As->addr_s_next;
						}
					}
					/* addr_s(N) */

					/* addr_s(N+1) */
					Ad[array_index].addr_s_next_file = Ad[array_index].addr_s_file->addr_s_next;
					/* addr_s(N+1) */

					/* addr_s(N-1) */
					if (Ts[keyword_hash].addr_s_N_first->id == file_set[i].id)
					{
						Ad[array_index].addr_s_prev_file = NULL;
					}
					else
					{
						if (i - 1 >= 0)
						{
							temp_As = Ts[keyword_hash].addr_s_N_first;
							while (1)
							{
								if (temp_As->id == file_set[i - 1].id)
								{
									Ad[array_index].addr_s_prev_file = temp_As;
									break;
								}
								else
								{
									temp_As = temp_As->addr_s_next;
								}
							}
						}
						else
						{
							Ad[array_index].addr_s_prev_file = NULL;
						}
					}
					/* addr_s(N-1) */
					array_index++;
				}
			}

			struct del_array *temp_Ad;

			/* build second element of Ts */
			for (int i = 0; i < 3; i++)
			{
				temp_As = Ts[F(keyword_set[i].keyword)].addr_s_N_first;
				temp_Ad = Td[F(temp_As->id)].addr_d_D_first;
				while (1)
				{
					if (temp_Ad->addr_s_file == temp_As)
					{
						Ts[F(keyword_set[i].keyword)].addr_d_N_first_dual = &(temp_Ad->addr_s_file);
						break;
					}
					else
					{
						temp_Ad = temp_Ad->addr_d_next;
					}
				}
			}
			/* build second element of Ts */

			/* build addr_d(N+1) */
			struct del_array *temp_Ad2;
			for (int i = 0; i < 3; i++)
			{
				temp_Ad = Td[F(file_set[i].id)].addr_d_D_first;
				while (1)
				{
					if (temp_Ad->addr_s_next_file != NULL)
					{
						temp_As = temp_Ad->addr_s_next_file;
						temp_Ad2 = Td[F(temp_As->id)].addr_d_D_first;
						while (1)
						{
							if (temp_Ad2->addr_s_file == temp_Ad->addr_s_next_file)
							{
								temp_Ad->addr_d_next_file = &(temp_Ad2->addr_s_file);
								break;
							}
							else
							{
								temp_Ad2 = temp_Ad2->addr_d_next;
							}
						}
					}
					else
					{
						temp_Ad->addr_d_next_file = NULL;
					}
					if (temp_Ad->addr_d_next == NULL)
					{
						break;
					}
					else
					{
						temp_Ad = temp_Ad->addr_d_next;
					}
				}

			}
			/* build addr_d(N+1) */

			/* build addr_d(N-1) */
			for (int i = 0; i < 3; i++)
			{
				temp_Ad = Td[F(file_set[i].id)].addr_d_D_first;
				while (1)
				{
					if (temp_Ad->addr_s_prev_file != 0)
					{
						temp_As = temp_Ad->addr_s_prev_file;
						temp_Ad2 = Td[F(temp_As->id)].addr_d_D_first;
						while (1)
						{
							if (temp_Ad2->addr_s_file == temp_Ad->addr_s_prev_file)
							{
								temp_Ad->addr_d_prev_file = &(temp_Ad2->addr_s_file);
								break;
							}
							else
							{
								temp_Ad2 = temp_Ad2->addr_d_next;
							}
						}

					}
					else
					{
						temp_Ad->addr_d_prev_file = NULL;
					}
					if (temp_Ad->addr_d_next == NULL)
					{
						break;
					}
					else
					{
						temp_Ad = temp_Ad->addr_d_next;
					}
				}
			}
			/* build addr_d(N-1) */

			cout << "Search index build complete" << endl;

			for (int i = 6; i < 8; i++)
			{
				As[i].id = '0';
				if (i == 7)
				{
					As[i].addr_s_next = NULL;
				}
				else
				{
					As[i].addr_s_next = As + i + 1;
				}				
				As[i].free_Ad = Ad + i;

				memset(Ad + i, NULL, sizeof(del_array));
			}

			Ts[F("free")].addr_s_N_first = &(As[6]);
			Ts[F("free")].addr_d_N_first_dual = NULL;

			cout << "Free index build complete" << endl;
		}

	
	private:
		byte k1[16], k2[16], k3[16], k4[16];
		struct index_keyword keyword_set[3];
		struct index_file file_set[3];

};

int main()
{
	DSSE DSSE_obj;
	DSSE_obj.keygen();
	DSSE_obj.index_build();
	DSSE_obj.enc();

	return 0;
}