#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <cstdlib>
#include <random>
#include <fstream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <windows.h>
#include <string>
#include <dirent.h>

#include <random>       // std::default_random_engine
#include <chrono>       // std::chrono::system_clock

#include <sha.h>
#include <osrng.h>
#include <hex.h>
#include <hmac.h>
#include <cmac.h>

#pragma comment(lib, "cryptlib.lib")

//#define ARRAY_SIZE 6 // equal to the number of file-keyword pairs
//#define FREE_SIZE 2
//#define SEARCH_TABLE_SIZE 65536 // equal to the number of keywords + 1
//#define DELETE_TABLE_SIZE 65536 // equal to the number of files

#define FREE "\"free\"" // used to identify the "free space" in search array

#define FILE_NUMBER 517375
#define KEYWPRD_NUMBER 1806218
#define PAIR_NUMBER 8 //105808042

#define KEY_LENGTH 16

using namespace std;
using namespace CryptoPP;

inline void string_to_byte(byte *b_text, string s_text, int b_text_len);  // parse a string raw data to an array

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

unsigned int F(byte *user_key, int user_key_len, string keyword, int unit_bytes, int index) // hash function
{
	string cmac = CMAC_AES_128(user_key, user_key_len, keyword);
	byte temp[16];
	string_to_byte(temp, cmac, 16);
	unsigned short int *ptr_2byte = NULL;
	unsigned int *ptr_4byte = NULL;
	if (unit_bytes == 2)
	{
		ptr_2byte = (unsigned short int*)temp;
		return ptr_2byte[index];
	}
	else if (unit_bytes == 4)
	{
		ptr_4byte = (unsigned int*)temp;
		return ptr_4byte[index];
	}
	else
	{
		cerr << "Error: parameter 4" << endl;
		return -1;
	}
	
}

struct search_array //As, for each keyword, 12 bytes, first 8 bytes encryption
{
	int file_id; // file ID is a 32-bit integer
	int addr_s_next; // the address of the next node in search array for a keyword
	int r; // for free As node, this is pointer to free Ad node
};

struct search_table // Ts, for each keyword, 8 bytes
{
	int addr_s_N_first; // the address of the first node in search array for a keyword
	int addr_d_N_first_dual; // the address of the first node in deletion array whose fourth entry points to the first node in search array for a keyword
	unsigned int keyword_hash;
};

struct del_array // Ad, for each file, 32 bytes
{
	int addr_d_next; // the address of the next node in deletion array for a file f
	int addr_d_prev_file; // the address of the fourth entry in deletion array which is points to the node for the next file f_+1 and keyword w
	int addr_d_next_file; // the address of the fourth entry in deletion array which is points to the node for the previous file f_+1 and keyword w
	int addr_s_file; // the address of the node in search array which is for keyword w that contain file f
	int addr_s_prev_file; // the address of the node in search array which is for keyword w that contain previous file f_-1
	int addr_s_next_file; // the address of the node in search array which is for keyword w that contain next file f_+1
	unsigned int keyword_hash;
	int r_p; // r'
};

struct del_table // Td, for each file, 4 bytes
{
	int addr_d_D_first;
	unsigned int file_hash;
};

/* auxiliary function */
inline void string_to_byte(byte *b_text, string s_text, int b_text_len)
{
	memcpy((char*)b_text, s_text.c_str(), b_text_len);
}

inline wstring s2ws(const std::string& s)
{
	int len;
	int slength = (int)s.length() + 1;
	len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
	std::wstring r(len, L'\0');
	MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, &r[0], len);
	return r;
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
/* auxiliary function */

class DSSE
{
	public:
		void client_keygen()
		{
			memset(k1, 0x01, sizeof(k1));
			memset(k2, 0x02, sizeof(k2));
			memset(k3, 0x03, sizeof(k3));
			memset(k4, 0x04, sizeof(k4));

			log_file.open(log_path, ios::out);
			if (!log_file)
				cerr << "Error: create log file " << log_path << " failed..." << endl;
		}
		
		void client_enc(int pair_number)
		{
			/* Mapping Index File to Memory */
			string index_path = "./Client/Index/Invert_Index.idx";
			string list_path = "./Client/List/Forward_Index.list";
			wstring w_index_path = s2ws(index_path);
			wstring w_list_path = s2ws(list_path);

			// 打開文件 for invert index
			HANDLE index_fileH = CreateFile(w_index_path.c_str(),
				GENERIC_READ | GENERIC_WRITE,
				FILE_SHARE_READ,
				NULL,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL,
				NULL);
			if (index_fileH == INVALID_HANDLE_VALUE)
			{
				cerr << "Error: CreateFile for " << index_path << endl;
				system("PAUSE");
				return;
			}
			int index_size = GetFileSize(index_fileH, NULL);

			// 創建文件映射內核對象
			HANDLE index_mapFileH = CreateFileMapping(index_fileH,
				NULL,
				PAGE_READWRITE,
				0,
				0,
				NULL);
			if (index_mapFileH == NULL)
			{
				cerr << "Error: CreateFileMapping for " << index_path << endl;
				system("PAUSE");
				return;
			}

			// 將文件數據映射到進程地址空間
			char *index_mapH = (char *)MapViewOfFile(index_mapFileH,
				FILE_MAP_ALL_ACCESS,
				0,
				0,
				0);
			if (index_mapH == NULL)
			{
				cerr << "Error: MapViewOfFile for" << index_path << endl;
				system("PAUSE");
				return;
			}
			
			// 設定存取指標
			char *index_ptr = index_mapH;
			/*for (int i = 0; i < index_size; i++)
			{
				cout << index_ptr[i];
			}*/
			
			// 打開文件 for list index
			HANDLE list_fileH = CreateFile(w_list_path.c_str(),
				GENERIC_READ | GENERIC_WRITE,
				FILE_SHARE_READ,
				NULL,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL,
				NULL);
			if (list_fileH == INVALID_HANDLE_VALUE)
			{
				cerr << "Error: CreateFile for " << list_path << endl;
				system("PAUSE");
				return;
			}
			int list_size = GetFileSize(list_fileH, NULL);

			// 創建文件映射內核對象
			HANDLE list_mapFileH = CreateFileMapping(list_fileH,
				NULL,
				PAGE_READWRITE,
				0,
				0,
				NULL);
			if (list_mapFileH == NULL)
			{
				cerr << "Error: CreateFileMapping for " << list_path << endl;
				system("PAUSE");
				return;
			}

			// 將文件數據映射到進程地址空間
			char *list_mapH = (char *)MapViewOfFile(list_mapFileH,
				FILE_MAP_ALL_ACCESS,
				0,
				0,
				0);
			if (list_mapH == NULL)
			{
				cerr << "Error: MapViewOfFile for" << list_path << endl;
				system("PAUSE");
				return;
			}

			// 設定存取指標
			char *list_ptr = list_mapH;
			/*for (int i = 0; i < list_size; i++)
			{
				cout << list_ptr[i];
			}*/
			/* Mapping Index File to Memory */
			
			/* For 32-bit random number r and r_p */
			random_device rd;
			default_random_engine eng{ rd() };
			uniform_int_distribution<> dist;
			/* For 32-bit random number r and r_p */

			int As_size = pair_number, Ad_size = pair_number, Ts_size = KEYWPRD_NUMBER + 1, Td_size = FILE_NUMBER;

			struct search_array *As; // equal to the number of file-keyword pairs
			struct del_array *Ad; // equal to the number of file-keyword pairs
			struct search_table *Ts; // equal to the number of keywords + 1
			struct del_table *Td; // equal to the number of files
		
			vector <int> As_index;
			vector <int> Ad_index;
			As_index.reserve(As_size);
			Ad_index.reserve(Ad_size);
			cout << "Generate random number for index As, Ad" << endl;
			cout << "	Start push back" << endl;
			
#pragma loop(hint_parallel(4)) // Auto-Parallelizer 

			for (int i = 0; i < As_size; i++)
			{
				As_index.push_back(i);
				Ad_index.push_back(i);
			}
			cout << "	Push back complete" << endl;

			cout << "	Start random shuffle" << endl;
			random_shuffle(As_index.begin(), As_index.end());
			random_shuffle(Ad_index.begin(), Ad_index.end());
			cout << "	Random shuffle complete" << endl;
			cout << "Random number gemerate complete" << endl;
			
			As = new struct search_array[As_size];
			Ad = new struct del_array[Ad_size];
			Ts = new struct search_table[Ts_size];
			Td = new struct del_table[Td_size];

			/* Initialization */
			memset(As, -1, As_size * sizeof(search_array));
			memset(Ad, -1, Ad_size * sizeof(del_array));
			memset(Ts, -1, Ts_size * sizeof(search_table));
			memset(Td, -1, Td_size * sizeof(del_table));
			/* Initialization */

			/* Build As */
			string keyword, file_ID, buf;
			int buf_head = 0, w_end, id_head, id_end, buf_size;
			int As_counter = 0, Ts_counter = 0;

			for (int i = 0; i < index_size; i++)
			{
				//cout << buf[i];
				if (index_ptr[i] == '\n')// buf裡的內容相當於getline得到的內容
				{
					buf.assign(index_ptr + buf_head, i - buf_head);
					//cout << buffer << endl;
					buf_size = buf.size();
					for (int j = 0; j < buf_size; j++)
					{
						if (buf[j] == ':') // read keyword from invert index
						{
							w_end = j;
							keyword.assign(buf.c_str(), w_end);
							Ts[Ts_counter].keyword_hash = F(k1, sizeof(k1), keyword, 4, 0); // record the keyword hash for store later
							Ts[Ts_counter].addr_s_N_first = As_index[As_counter]; // build first element of Ts
							Ts_counter++;
							//cout << Ts_counter << endl; // show the Ts_counter
							//cout << keyword << endl; // show the keyword
							id_head = w_end + 1;
							break;
						}
					}

					for (int j = id_head; j < buf_size; j++) // read file ID from invert index
					{
						if (buf[j] == 32)
						{
							id_end = j;
							file_ID.assign(&buf[id_head], id_end - id_head);
							id_head = id_end + 1;
							//cout << file_ID << endl; //show the ID
							
							//cout << "As_index[counter] = " << As_index[counter] << endl;
							As[As_index[As_counter]].file_id = atoi(file_ID.c_str()); // store ID to As
							As[As_index[As_counter]].r = dist(eng); // generate r
							As[As_index[As_counter]].addr_s_next = As_index[As_counter + 1]; // link to next node for the same keyword
							As_counter++;
						}
					}
					As[As_index[As_counter-1]].addr_s_next = -1; // let array_index < 0 as NULL

					buf_head = i + 1;
				}
			}
			/* Build As */

			/* Build Ad Part */
			keyword.clear();
			file_ID.clear();
			buf.clear();
			buf_head = 0, id_end = 0;
			int keyword_head, keyword_end;
			int Ad_counter = 0, Td_counter = 0;

			unsigned int keyword_hash;
			int temp_As_index;
			
			for (int i = 0; i < list_size; i++)
			{
				//cout << list_ptr[i];
				if (list_ptr[i] == '\n')// buf裡的內容相當於getline得到的內容
				{
					buf.assign(list_ptr + buf_head, i - buf_head);
					//cout << buf << endl;
					buf_size = buf.size();

					for (int j = 0; j < buf_size; j++)
					{
						if (buf[j] == ':') // read file ID from forward index
						{
							id_end = j;
							file_ID.assign(buf.c_str(), id_end);
							Td[Td_counter].file_hash = F(k1, sizeof(k1), file_ID, 4, 0); // record the file hash for store later
							Td[Td_counter].addr_d_D_first = Ad_index[Ad_counter]; // build Td
							Td_counter++;
							//cout << Ts_counter << endl; // show the Ts_counter
							//cout << file_ID << endl; // show the file ID
							keyword_head = id_end + 1;
							break;
						}
					}

					for (int j = keyword_head; j < buf_size; j++) // read keyword from forward index
					{
						if (buf[j] == 32)
						{
							keyword_end = j;
							keyword.assign(&buf[keyword_head], keyword_end - keyword_head);
							keyword_head = keyword_end + 1;
							//cout << keyword << endl; //show the keyword

							keyword_hash = F(k1, sizeof(k1), keyword, 4, 0);
							Ad[Ad_index[Ad_counter]].keyword_hash = keyword_hash; // F(w)
							Ad[Ad_index[Ad_counter]].r_p = dist(eng); // r'
							Ad[Ad_index[Ad_counter]].addr_d_next = Ad_index[Ad_counter + 1]; // link to next node for the same ID

							/* addr_s(N) */
							for (int k = 0; k < Ts_counter; k++)
							{
								if (keyword_hash == Ts[k].keyword_hash)
								{
									temp_As_index = Ts[k].addr_s_N_first;
									//cout << "temp_As_index = " << temp_As_index << endl;
									break;
								}
							}
							while (1)
							{
								if (As[temp_As_index].file_id == atoi(file_ID.c_str()))
								{
									Ad[Ad_index[Ad_counter]].addr_s_file = temp_As_index;
									//cout << "temp_As_index = " << temp_As_index << endl;
									break;
								}
								else
								{
									temp_As_index = As[temp_As_index].addr_s_next;
								}
							}
							/* addr_s(N) */

							Ad[Ad_index[Ad_counter]].addr_s_next_file = As[Ad[Ad_index[Ad_counter]].addr_s_file].addr_s_next; // addr_s(N+1)

							
							/* addr_s(N-1) */
							for (int k = 0; k < Ts_counter; k++)
							{
								if (keyword_hash == Ts[k].keyword_hash)
								{
									temp_As_index = Ts[k].addr_s_N_first;
									//cout << "temp_As_index = " << temp_As_index << endl;
									break;
								}
							}
							if (As[temp_As_index].file_id == atoi(file_ID.c_str())) // if we can find it Ts, there is no previous node
							{
								Ad[Ad_index[Ad_counter]].addr_s_prev_file = -1;
							}
							else
							{
								while (1)
								{
									if (As[temp_As_index].addr_s_next == Ad[Ad_index[Ad_counter]].addr_s_file)
									{
										Ad[Ad_index[Ad_counter]].addr_s_prev_file = temp_As_index;
										break;
									}
									else
									{
										temp_As_index = As[temp_As_index].addr_s_next;
									}
								}
							}
							/* addr_s(N-1) */
							Ad_counter++;
						}
					}
					Ad[Ad_index[Ad_counter - 1]].addr_d_next = -1; // let array_index < 0 as NULL
					buf_head = i + 1;
				}
			}
			/* Build Ad Part */

			/* Build Second Element of Ts */
			buf_head = 0;
			unsigned int file_hash;
			int temp_Ad_index, temp_Td_index;;
			for (int i = 0; i < index_size; i++)
			{
				//cout << buf[i];
				if (index_ptr[i] == '\n')// buf裡的內容相當於getline得到的內容
				{
					buf.assign(index_ptr + buf_head, i - buf_head);
					//cout << buffer << endl;
					buf_size = buf.size();
					for (int j = 0; j < buf_size; j++)
					{
						if (buf[j] == ':') // read keyword from invert index
						{
							w_end = j;
							keyword.assign(buf.c_str(), w_end);
							//cout << keyword << endl; // show the keyword
							break;
						}
					}
					buf_head = i + 1;

					keyword_hash = F(k1, sizeof(k1), keyword, 4, 0);

					for (int k = 0; k < Ts_counter; k++)
					{
						if (keyword_hash == Ts[k].keyword_hash)
						{
							temp_As_index = Ts[k].addr_s_N_first;
							temp_Td_index = k;
							//cout << "temp_As_index = " << temp_As_index << endl;
							break;
						}
					}
					file_ID = to_string(As[temp_As_index].file_id);
					file_hash = F(k1, sizeof(k1), file_ID, 4, 0);

					for (int k = 0; k < Td_counter; k++)
					{
						if (file_hash == Td[k].file_hash)
						{
							temp_Ad_index = Td[k].addr_d_D_first;
							break;
						}
					}
					while (1)
					{
						if (Ad[temp_Ad_index].addr_s_file == temp_As_index)
						{
							Ts[temp_Td_index].addr_d_N_first_dual = temp_Ad_index;
							break;
						}
						else
						{
							temp_Ad_index = Ad[temp_Ad_index].addr_d_next;
						}
					}
				}
			}
			/* Build Second Element of Ts */

			/* Build addr_d(N+1) */
			buf_head = 0;
			int temp_Ad_index2;
			for (int i = 0; i < list_size; i++)
			{
				//cout << list_ptr[i];
				if (list_ptr[i] == '\n')// buf裡的內容相當於getline得到的內容
				{
					buf.assign(list_ptr + buf_head, i - buf_head);
					//cout << buf << endl;
					buf_size = buf.size();

					for (int j = 0; j < buf_size; j++)
					{
						if (buf[j] == ':') // read file ID from forward index
						{
							id_end = j;
							file_ID.assign(buf.c_str(), id_end);
							cout << file_ID << endl; // show the file ID
							break;
						}
					}
					buf_head = i + 1;

					file_hash = F(k1, sizeof(k1), file_ID, 4, 0);

					for (int k = 0; k < Td_counter; k++)
					{
						if (file_hash == Td[k].file_hash)
						{
							temp_Ad_index = Td[k].addr_d_D_first;
							break;
						}
					}

					while (1)
					{
						if (Ad[temp_Ad_index].addr_s_next_file != -1)
						{
							temp_As_index = Ad[temp_Ad_index].addr_s_next_file;
							file_ID = to_string(As[temp_As_index].file_id);
							file_hash = F(k1, sizeof(k1), file_ID, 4, 0);
							for (int k = 0; k < Td_counter; k++)
							{
								if (file_hash == Td[k].file_hash)
								{
									temp_Ad_index2 = Td[k].addr_d_D_first;
									break;
								}
							}
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
			}
			/* Build addr_d(N+1) */

			/* Build addr_d(N-1) */
			buf_head = 0;
			for (int i = 0; i < list_size; i++)
			{
				//cout << list_ptr[i];
				if (list_ptr[i] == '\n')// buf裡的內容相當於getline得到的內容
				{
					buf.assign(list_ptr + buf_head, i - buf_head);
					//cout << buf << endl;
					buf_size = buf.size();

					for (int j = 0; j < buf_size; j++)
					{
						if (buf[j] == ':') // read file ID from forward index
						{
							id_end = j;
							file_ID.assign(buf.c_str(), id_end);
							//cout << file_ID << endl; // show the file ID
							break;
						}
					}
					buf_head = i + 1;

					file_hash = F(k1, sizeof(k1), file_ID, 4, 0);

					for (int k = 0; k < Td_counter; k++)
					{
						if (file_hash == Td[k].file_hash)
						{
							temp_Ad_index = Td[k].addr_d_D_first;
							break;
						}
					}

					while (1)
					{
						if (Ad[temp_Ad_index].addr_s_prev_file != -1)
						{
							temp_As_index = Ad[temp_Ad_index].addr_s_prev_file;
							file_ID = to_string(As[temp_As_index].file_id);
							file_hash = F(k1, sizeof(k1), file_ID, 4, 0);
							for (int k = 0; k < Td_counter; k++)
							{
								if (file_hash == Td[k].file_hash)
								{
									temp_Ad_index2 = Td[k].addr_d_D_first;
									break;
								}
							}
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
			}
			/* Build addr_d(N-1) */
			cout << "Search index build complete" << endl;

			/*
			for (int i = 0; i < As_counter; i++) // show the state in As[]
			{
				cout << "As[" << As_index[i] << "].file_id     = " << As[As_index[i]].file_id << endl;
				cout << "As[" << As_index[i] << "].addr_s_next = " << As[As_index[i]].addr_s_next << endl;
				cout << "As[" << As_index[i] << "].r           = " << As[As_index[i]].r << endl;
				cout << endl;
			}

			for (int i = 0; i < Ad_counter; i++) // show the state in Ad[]
			{
				cout << "Ad[" << Ad_index[i] << "].addr_d_next      = " << Ad[Ad_index[i]].addr_d_next << endl;
				cout << "Ad[" << Ad_index[i] << "].addr_d_prev_file = " << Ad[Ad_index[i]].addr_d_prev_file << endl;
				cout << "Ad[" << Ad_index[i] << "].addr_d_next_file = " << Ad[Ad_index[i]].addr_d_next_file << endl;
				cout << "Ad[" << Ad_index[i] << "].addr_s_file      = " << Ad[Ad_index[i]].addr_s_file << endl;
				cout << "Ad[" << Ad_index[i] << "].addr_s_prev_file = " << Ad[Ad_index[i]].addr_s_prev_file << endl;
				cout << "Ad[" << Ad_index[i] << "].addr_s_next_file = " << Ad[Ad_index[i]].addr_s_next_file << endl;
				cout << "Ad[" << Ad_index[i] << "].keyword_hash     = " << Ad[Ad_index[i]].keyword_hash << endl;
				cout << "Ad[" << Ad_index[i] << "].r_p = " << Ad[Ad_index[i]].r_p << endl;
				cout << endl;
			}

			for (int i = 0; i < Ts_counter; i++) // show the state in Ts[]
			{
				cout << "Ts[" << i << "].keyword_hash   = " << Ts[i].keyword_hash << endl;
				cout << "Ts[" << i << "].addr_s_N_first = " << Ts[i].addr_s_N_first << endl;
				cout << endl;
			}

			for (int i = 0; i < Td_counter; i++) // show the state in Td[]
			{
				cout << "Td[" << i << "].file_hash      = " << Td[i].file_hash << endl;
				cout << "Td[" << i << "].addr_d_D_first = " << Td[i].addr_d_D_first << endl;
				cout << endl;
			}
			*/

			/* For free As and Ad */
			string free_str = FREE;
			Ts[Ts_counter].keyword_hash = F(k1, sizeof(k1), free_str, 4, 0);
			Ts[Ts_counter].addr_s_N_first = As_index[As_size - 1];
			cout << "Number of free array: " << As_size - As_counter << endl;
			for (int i = As_size - 1; i >= As_counter; i--)
			{
				As[As_index[i]].file_id = -1;

				if (i == As_counter)
					As[As_index[i]].addr_s_next = -1;
				else
					As[As_index[i]].addr_s_next = As_index[i - 1];

				As[As_index[i]].r = Ad_index[i];

				Ad[Ad_index[i]].addr_d_next = dist(eng);
				Ad[Ad_index[i]].addr_d_next_file = dist(eng);
				Ad[Ad_index[i]].addr_d_prev_file = dist(eng);
				Ad[Ad_index[i]].addr_s_file = dist(eng);
				Ad[Ad_index[i]].addr_s_next_file = dist(eng);
				Ad[Ad_index[i]].addr_s_prev_file = dist(eng);
				Ad[Ad_index[i]].keyword_hash = dist(eng);
				Ad[Ad_index[i]].r_p = dist(eng);
			}
			/* For free As and Ad */
			cout << "Free index build complete" << endl;
			cout << "Random data write complete" << endl;

			/* Encryption As */
			cout << "Encryption As..." << endl;
			char *temp_ptr;
			string Kw, H1;
			buf_head = 0;
			for (int i = 0; i < index_size; i++)
			{
				//cout << buf[i];
				if (index_ptr[i] == '\n')// buf裡的內容相當於getline得到的內容
				{
					buf.assign(index_ptr + buf_head, i - buf_head);
					//cout << buffer << endl;
					buf_size = buf.size();
					for (int j = 0; j < buf_size; j++)
					{
						if (buf[j] == ':') // read keyword from invert index
						{
							w_end = j;
							keyword.assign(buf.c_str(), w_end);
							//cout << keyword << endl; // show the keyword
							Kw = CMAC_AES_128(k3, sizeof(k3), keyword); // fora keyword, generate a key for HMAC_SHA_256
							keyword_hash = F(k1, sizeof(k1), keyword, 4, 0);
							for (int k = 0; k < Ts_counter; k++)
							{
								if (keyword_hash == Ts[k].keyword_hash)
								{
									temp_As_index = Ts[k].addr_s_N_first;
									//cout << "temp_As_index = " << temp_As_index << endl;
									break;
								}
							}
							while (temp_As_index != -1)
							{
								H1 = HMAC_SHA_256((byte*)Kw.c_str(), Kw.size(), to_string(As[temp_As_index].r)); // generate a 256-bit key
								temp_ptr = (char*)&As[temp_As_index];
								temp_As_index = As[temp_As_index].addr_s_next;
								for (int j = 0; j < 8; j++)
								{
									temp_ptr[j] = temp_ptr[j] ^ H1.c_str()[j];
								}
							}
							break;
						}
					}
					buf_head = i + 1;
				}
			}
			/* Encryption As */

			/* Encryption Ad */
			cout << "Encryption Ad..." << endl;
			string Kf, H2;
			buf_head = 0;
			for (int i = 0; i < list_size; i++)
			{
				//cout << list_ptr[i];
				if (list_ptr[i] == '\n')// buf裡的內容相當於getline得到的內容
				{
					buf.assign(list_ptr + buf_head, i - buf_head);
					//cout << buf << endl;
					buf_size = buf.size();

					for (int j = 0; j < buf_size; j++)
					{
						if (buf[j] == ':') // read file ID from forward index
						{
							id_end = j;
							file_ID.assign(buf.c_str(), id_end);
							//cout << file_ID << endl; // show the file ID
							file_hash = F(k1, sizeof(k1), file_ID, 4, 0);
							Kf = CMAC_AES_128(k3, sizeof(k3), file_ID);
							
							for (int k = 0; k < Td_counter; k++)
							{
								if (file_hash == Td[k].file_hash)
								{
									temp_Ad_index = Td[k].addr_d_D_first;
									break;
								}
							}

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
							break;
						}
					}
					buf_head = i + 1;
				}
			}
			/* Encryption Ad */


			/* Encryption  Ts */
			cout << "Encryption  Ts..." << endl;
			string G_k2_w;
			buf_head = 0;
			int temp_Ts_index;
			for (int i = 0; i < index_size; i++)
			{
				//cout << buf[i];
				if (index_ptr[i] == '\n')// buf裡的內容相當於getline得到的內容
				{
					buf.assign(index_ptr + buf_head, i - buf_head);
					//cout << buffer << endl;
					buf_size = buf.size();
					for (int j = 0; j < buf_size; j++)
					{
						if (buf[j] == ':') // read keyword from invert index
						{
							w_end = j;
							keyword.assign(buf.c_str(), w_end);
							//cout << keyword << endl; // show the keyword
							keyword_hash = F(k1, sizeof(k1), keyword, 4, 0);
							for (int k = 0; k < Ts_counter; k++)
							{
								if (keyword_hash == Ts[k].keyword_hash)
								{
									temp_Ts_index = k;
									//cout << "temp_Ts_index = " << temp_Ts_index << endl;
									break;
								}
							}

							G_k2_w = CMAC_AES_128(k2, sizeof(k2), keyword);
							temp_ptr = (char*)&Ts[temp_Ts_index];
							for (int j = 0; j < 8; j++)
							{
								temp_ptr[j] = temp_ptr[j] ^ G_k2_w.c_str()[j];
							}
							break;
						}
					}
					buf_head = i + 1;
				}
			}
			/* Encryption  Ts */

			/* Encryption Td */
			cout << "Encryption Td..." << endl;
			string G_k2_f;
			buf_head = 0;
			for (int i = 0; i < list_size; i++)
			{
				//cout << list_ptr[i];
				if (list_ptr[i] == '\n')// buf裡的內容相當於getline得到的內容
				{
					buf.assign(list_ptr + buf_head, i - buf_head);
					//cout << buf << endl;
					buf_size = buf.size();

					for (int j = 0; j < buf_size; j++)
					{
						if (buf[j] == ':') // read file ID from forward index
						{
							id_end = j;
							file_ID.assign(buf.c_str(), id_end);
							//cout << file_ID << endl; // show the file ID
							file_hash = F(k1, sizeof(k1), file_ID, 4, 0);

							for (int k = 0; k < Td_counter; k++)
							{
								if (file_hash == Td[k].file_hash)
								{
									temp_Td_index = k;
									//cout << "temp_Td_index = " << temp_Td_index << endl;
									break;
								}
							}
							G_k2_f = CMAC_AES_128(k2, sizeof(k2), file_ID);
							temp_ptr = (char*)&Td[temp_Td_index];
							for (int j = 0; j < 4; j++)
							{
								temp_ptr[j] = temp_ptr[j] ^ G_k2_f.c_str()[j];
							}
							break;
						}
					}
					buf_head = i + 1;
				}
			}
			/* Encryption Td */

			fstream enc_dest_1, enc_dest_2;
			string path_1, path_2;
			/* Write Ts, Td to server */
			for (int i = 0; i < Ts_counter; i++) // + 1 for "FREE"
			{
				path_1 = "./Server/Ts/Ts_" + to_string(Ts[i].keyword_hash) + ".enc";
				//cout << "Create file: " << path_1 << endl;
				enc_dest_1.open(path_1, ios::out | ios::binary);
				if (!enc_dest_1)
					cerr << "Destination file create failed." << endl << endl;
				enc_dest_1.write((char*)&Ts[i], 8);
				enc_dest_1.close();

				path_2 = "./Server/Td/Td_" + to_string(Td[i].file_hash) + ".enc";
				//cout << "Create file: " << path_2 << endl;
				enc_dest_2.open(path_2, ios::out | ios::binary);
				if (!enc_dest_2)
					cerr << "Destination file create failed." << endl << endl;
				enc_dest_2.write((char*)&Td[i], 4);
				enc_dest_2.close();
			}
			/* Write Ts, Td to server */

			/* Write Ts["FREE"] */
			path_1 = "./Server/Ts/Ts_" + to_string(Ts[Ts_counter].keyword_hash) + ".enc";
			//cout << "Create file: " << path_1 << endl;
			enc_dest_1.open(path_1, ios::out | ios::binary);
			if (!enc_dest_1)
				cerr << "Destination file create failed." << endl << endl;
			enc_dest_1.write((char*)&Ts[Ts_counter], 8);
			enc_dest_1.close();
			/* Write Ts["FREE"] */

			/* Write As, Ad to server */
			for (int i = 0; i < As_counter; i++)
			{
				path_1 = "./Server/As/As_" + to_string(i) + ".enc";
				//cout << "Create file: " << path_1 << endl;
				enc_dest_1.open(path_1, ios::out | ios::binary);
				if (!enc_dest_1)
					cerr << "Destination file create failed." << endl << endl;
				enc_dest_1.write((char*)&As[i], sizeof(As[i]));
				enc_dest_1.close();

				path_2 = "./Server/Ad/Ad_" + to_string(i) + ".enc";
				//cout << "Create file: " << path_2 << endl;
				enc_dest_2.open(path_2, ios::out | ios::binary);
				if (!enc_dest_2)
					cerr << "Destination file create failed." << endl << endl;
				enc_dest_2.write((char*)&Ad[i], sizeof(Ad[i]));
				enc_dest_2.close();
			}
			/* Write As, Ad to server */

			/* Write Free As, Ad */
			for (int i = As_counter; i < As_size; i++)
			{
				path_1 = "./Server/As/As_" + to_string(i) + ".enc";
				//cout << "Create file: " << path_1 << endl;
				enc_dest_1.open(path_1, ios::out | ios::binary);
				if (!enc_dest_1)
					cerr << "Destination file create failed." << endl << endl;
				enc_dest_1.write((char*)&As[i], sizeof(As[i]));
				enc_dest_1.close();

				path_2 = "./Server/Ad/Ad_" + to_string(i) + ".enc";
				//cout << "Create file: " << path_2 << endl;
				enc_dest_2.open(path_2, ios::out | ios::binary);
				if (!enc_dest_2)
					cerr << "Destination file create failed." << endl << endl;
				enc_dest_2.write((char*)&Ad[i], sizeof(Ad[i]));
				enc_dest_2.close();
			}
			/* Write Free As, Ad */

			delete[] As;
			delete[] Ad;
			delete[] Ts;
			delete[] Td;

			UnmapViewOfFile(index_mapH);
			CloseHandle(index_mapFileH);
			CloseHandle(index_fileH);

			UnmapViewOfFile(list_mapH);
			CloseHandle(list_mapFileH);
			CloseHandle(list_fileH);
		}

		void client_srch_token(string keyword, unsigned int *F_k1_w, string *G_k2_w, string *P_k3_w)
		{
			*F_k1_w = F(k1, sizeof(k1), keyword, 4, 0);
			*G_k2_w = CMAC_AES_128(k2, sizeof(k2), keyword);
			*P_k3_w = CMAC_AES_128(k3, sizeof(k3), keyword);
		}

		void server_search(unsigned int F_k1_w, string G_k2_w, string P_k3_w)
		{
			struct search_table temp_Ts;
			struct search_array temp_As;
			char *temp_ptr;
			string H1;

			cout << "Search Token: " << endl;
			cout << "	F_k1_w:" << F_k1_w << ", G_k2_w: " << hex_encoder(G_k2_w) << ", P_k3_w: " << hex_encoder(P_k3_w) << endl;
			log_file << "Search Token: " << endl;
			log_file << "	F_k1_w:" << F_k1_w << ", G_k2_w: " << hex_encoder(G_k2_w) << ", P_k3_w: " << hex_encoder(P_k3_w) << endl;
			

			fstream enc_src;
			string path = "./Server/Ts/Ts_" + to_string(F_k1_w) + ".enc";
			//cout << "Open file: " << path << endl;
			enc_src.open(path, ios::in | ios::binary);
			if (!enc_src)
			{
				cerr << "No such file: " << path << endl << endl;
				log_file << "No such file." << path << endl << endl;
			}
			else
			{
				enc_src.read((char*)&temp_Ts, 8);
				enc_src.close();
				temp_ptr =(char*)&temp_Ts;
				
				for (int i = 0; i < 8; i++)
				{
					temp_ptr[i] = temp_ptr[i] ^ G_k2_w.c_str()[i]; // decryption Ts
				}
				
				path = "./Server/As/As_" + to_string(temp_Ts.addr_s_N_first) + ".enc";
				//cout << "Open file: " << path << endl;
				enc_src.open(path, ios::in | ios::binary);
				if (!enc_src)
				{
					cerr << "No such file: " << path << endl << endl;
					log_file << "No such file: " << path << endl << endl;
				}
				else
				{
					enc_src.read((char*)&temp_As, sizeof(temp_As));
					enc_src.close();
					temp_ptr = (char*)&temp_As;
					H1 = HMAC_SHA_256((byte*)P_k3_w.c_str(), P_k3_w.size(), to_string(temp_As.r)); // calculate a 256-bit key
					for (int i = 0; i < 8; i++)
					{
						temp_ptr[i] = temp_ptr[i] ^ H1.c_str()[i];
					}
					//cout << "Return file ID: " << temp_As.file_id << endl;
					log_file << "Return file ID: " << temp_As.file_id << endl;
					while (temp_As.addr_s_next != -1)
					{
						path = "./Server/As/As_" + to_string(temp_As.addr_s_next) + ".enc";
						//cout << "Open file: " << path << endl;
						enc_src.open(path, ios::in | ios::binary);
						if (!enc_src)
						{
							cerr << "No such file: " << path << endl << endl;
							log_file << "No such file: " << path << endl << endl;
							break;
						}
						else
						{
							enc_src.read((char*)&temp_As, sizeof(temp_As));
							enc_src.close();
							temp_ptr = (char*)&temp_As;
							H1 = HMAC_SHA_256((byte*)P_k3_w.c_str(), P_k3_w.size(), to_string(temp_As.r)); // calculate a 256-bit key
							for (int i = 0; i < 8; i++)
							{
								temp_ptr[i] = temp_ptr[i] ^ H1.c_str()[i];
							}
							//cout << "Return file ID: " << temp_As.file_id << endl;
							log_file << "Return file ID: " << temp_As.file_id << endl;
						}
					}
				}
			}
			log_file << endl;
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

			memset(&Ad, 0, sizeof(Ad));

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

				//string_to_byte((byte*)As.id, file_name_hash, 32); // store ID to As
				As.addr_s_next = 0;

				Ad.keyword_hash = F_k1_w;
				//Ad.addr_d_next = Ad.addr_d_next_file = Ad.addr_d_prev_file = Ad.addr_s_file = Ad.addr_s_next_file = Ad.addr_s_prev_file = 0;

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
			fstream token_file; // composed of F_k1_f, G_k2_f, F_k1_w, G_k2_w, As, Ad
			fstream Td_file, Ts_file, As_file, Ad_file, next_As_file;
			string Td_path, Ts_path, As_path, Ad_path;
			char *ptr1 = NULL;

			int F_k1_w, F_k1_f;
			char buf[16]; // to buffer G_k2_w and G_k2_f
			string G_k2_w, G_k2_f;
			
			struct search_array As, token_As, free_As;
			struct del_array Ad, token_Ad;
			struct search_table Ts, free_Ts;
			struct del_table Td;
			//int new_N_first, new_N_first_dual;
			int As_free_i, Ad_free_i, As_free_i_next, Ad_free_i_next, As_w, Ad_w;

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
				
				/* Create a new Td[F_k1_f] */
				Td_path = "./EncData/Td_" + to_string(F_k1_f) + ".enc";
				cout << "Create a new Td file: " << Td_path << endl;
				Td_file.open(Td_path, ios::out | ios::binary);
				if (!Td_file)
				{
					cerr << "Error: create new Td file failed." << endl;
					return;
				}
				/* Create a new Td[F_k1_f] */
				
				while ((int)token_file.tellg() != length)
				{
					token_file.read((char*)&F_k1_w, sizeof(F_k1_w));
					token_file.read(buf, sizeof(buf));
					G_k2_w.assign(buf, sizeof(buf));
					token_file.read((char*)&token_As, sizeof(token_As));
					token_file.read((char*)&token_Ad, sizeof(token_Ad));

					Ts_path = "./EncData/Ts_Free"; // Open Ts_Free
					cout << "Retrive free As index from file: " << Ts_path << endl;
					Ts_file.open(Ts_path, ios::in | ios::out | ios::binary);
					if (!Ts_file)
					{
						cerr << "Error: open " << Ts_path << " failed..." << endl;
					}
					else
					{
						Ts_file.read((char*)&free_Ts, sizeof(free_Ts));
						Ts_file.seekg(0, Ts_file.beg);

						cout << "Free As index: " << free_Ts.addr_s_N_first << endl;
						As_free_i = free_Ts.addr_s_N_first; // free As index, Phi

						As_path = "./EncData/As_" + to_string(As_free_i) + ".enc"; // Open free As
						cout << "Open free As file: " << As_path << endl;
						As_file.open(As_path, ios::in | ios::out | ios::binary);
						if (!As_file)
						{
							cerr << "Error: open file: " << As_path << " failed..." << endl;
						}
						else
						{
							As_file.read((char*)&free_As, sizeof(free_As));
							As_file.seekg(0, As_file.beg);
							As_free_i_next = free_As.addr_s_next;
							Ad_free_i = free_As.r; // the corresponding Ad, Phi*
							
							cout << "The corresponding Ad index: " << Ad_free_i << endl;

							if (Ad_free_i == -1)
								cout << "As already is full!" << endl;
							else
								cout << "Next free As index: " << As_free_i_next << endl; // Phi_prev

							/* Update Ts_free table */
							free_Ts.addr_s_N_first = As_free_i_next;
							Ts_file.write((char*)&free_Ts, sizeof(free_Ts)); // update search table Ts for free
							Ts_file.close();
							cout << "**** Update Free Ts table to point to As_" << free_As.addr_s_next << " .enc ****" << endl;
							/* Update Ts_free table */

							Ts_path = "EncData/Ts_" + to_string(F_k1_w) +".enc"; // open Ts for a keywoord
							Ts_file.open(Ts_path, ios::in | ios::out | ios::binary);
							if (!Ts_file)
							{
								cerr << "Error: open file: " << Ts_path << " failed..." << endl;
							}
							else
							{
								cout << "Open search table Ts file for some keyword: " << Ts_path << endl;
								Ts_file.read((char*)&Ts, sizeof(Ts));
								Ts_file.seekg(0, Ts_file.beg);
								ptr1 = (char*)&Ts;
								for (int i = 0; i < sizeof(Ts); i++) // decryption Ts
								{
									ptr1[i] = ptr1[i] ^ G_k2_w.c_str()[i];
								}
								As_w = Ts.addr_s_N_first; // Alpha
								Ad_w = Ts.addr_d_N_first_dual; // Alpha*
								cout << "First As index for some keyword: " << As_w << endl; 
								cout << "Dual Ad index for some keyword: " << Ad_w << endl;

								/* Write data to free As */
								token_As.addr_s_next = token_As.addr_s_next ^ As_w;
								As_file.write((char*)&token_As, sizeof(token_As));
								As_file.close();
								cout << "**** Write new data to free As file: " << As_path << " ****" << endl;
								/* Write data to free As */

								/* Update the corrsponding Ad for some keyword */
								Ad_path = "./EncData/Ad_" + to_string(Ad_w) + ".enc";
								cout << "Open dual Ad file for some keyword: " << Ad_path << endl;
								Ad_file.open(Ad_path, ios::in | ios::out | ios::binary);
								if (!Ad_file)
								{
									cerr << "Error: open file: " << Ad_path << " failed." << endl;
								}
								else
								{
									Ad_file.read((char*)&Ad, sizeof(Ad));
									Ad_file.seekg(0, Ad_file.beg);

									Ad.addr_d_prev_file = Ad.addr_d_prev_file ^ -1 ^ Ad_free_i; // -1: for the first As, the original value is - 1
									Ad.addr_s_prev_file = Ad.addr_s_prev_file ^ -1 ^ As_free_i;
									
									Ad_file.write((char*)&Ad, sizeof(Ad));
									Ad_file.close();
									cout << "**** Update the corrsponding Ad for some keyword: " << Ad_path << " ****" << endl;
								}
								/* Update the corrsponding Ad for some keyword */
								
								/* Update search table for some keyword */
								Ts.addr_s_N_first = As_free_i;
								Ts.addr_d_N_first_dual = Ad_free_i;
								ptr1 = (char*)&Ts;
								for (int i = 0; i < sizeof(Ts); i++) // re-ecryption Ts
								{
									ptr1[i] = ptr1[i] ^ G_k2_w.c_str()[i];
								}
								Ts_file.write((char*)&Ts, sizeof(Ts));
								Ts_file.close();
								cout << "**** Update search table for some keyword: " << Ts_path << " ****" << endl;
								/* Update search table for some keyword */

								/* Update new Ad for new file */
								Ad_path = "./EncData/Ad_" + to_string(Ad_free_i) + ".enc";
								Ad_file.open(Ad_path, ios::in | ios::out | ios::binary);
								if (!Ad_file)
								{
									cerr << "Error: open file: " << Ad_path << " failed...." << endl;
								}
								else
								{
									cout << "Open free Ad file: " << Ad_path << endl;

									if ((int)token_file.tellg() == length)
										token_Ad.addr_d_next = token_Ad.addr_d_next ^ - 1; // Phi*_prev
									else
									{
										As_path = "./EncData/As_" + to_string(As_free_i_next) + ".enc";
										As_file.open(As_path, ios::in | ios::binary);
										if (!Ad_file)
										{
											cerr << "Error: open file: " << As_path << " failed...." << endl;
										}
										else
										{
											cout << "Open next free As file: " << As_path << "to find next Ad" << endl;
											As_file.read((char*)&As, sizeof(As));
											As_file.close();
											token_Ad.addr_d_next = token_Ad.addr_d_next ^ As.r;
										}
									}
									token_Ad.addr_d_prev_file = token_Ad.addr_d_prev_file ^ -1;
									token_Ad.addr_d_next_file = token_Ad.addr_d_next_file ^ Ad_w;
									token_Ad.addr_s_file = token_Ad.addr_s_file ^ As_free_i;
									token_Ad.addr_s_prev_file = token_Ad.addr_s_prev_file ^ -1;
									token_Ad.addr_s_next_file = token_Ad.addr_s_next_file ^ As_w;

									Ad_file.write((char*)&token_Ad, sizeof(token_Ad));
									Ad_file.close();
									cout << "**** Write data to new Ad file: " << Ad_path << " ****" << endl;
								}
								/* Update new Ad for new file */
							}
						}
					}
				}
				Td.addr_d_D_first = Ad_free_i;
				ptr1 = (char*)&Td;
				for (int i = 0; i < sizeof(Td); i++)
				{
					ptr1[i] = ptr1[i] ^ G_k2_f.c_str()[i];
				}
				Td_file.write((char*)&Td, sizeof(Td));
				Td_file.close();
				cout << "Let Td file: " << Td_path << " point to Ad_" << Ad_free_i << ".enc" << endl;
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
								//memset(As.id, -1, 32);
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
		byte k1[KEY_LENGTH], k2[KEY_LENGTH], k3[KEY_LENGTH], k4[KEY_LENGTH];

		fstream log_file;
		string log_path = "./DSSE_Search_Result.txt";

		//struct search_array As[ARRAY_SIZE + FREE_SIZE];
		//struct del_array Ad[ARRAY_SIZE + FREE_SIZE];
		//struct search_table Ts[SEARCH_TABLE_SIZE];
		//struct del_table Td[DELETE_TABLE_SIZE];
};

int main()
{
	DSSE DSSE_obj;

	unsigned int F_k1_w; // search token
	string G_k2_w, P_k3_w; //search token
	string keyword, file_name;
	string add_token; // add token file path

	int F_k1_f; // selete tokwn
	string G_k2_f, P_k3_f; //delete token
	string sha256_id;

	fstream log_file;
	log_file.open("./DSSE_Kamara_Log.txt", ios::out);
	
	int opcode;
	int pair_number;
	cout << "Enter the number of file-keyword pairs for the database:" << endl << ">>";
	cin >> pair_number;

	DSSE_obj.client_keygen();
	cout << "Key generateion complete." << endl;

	cout << endl << "Enter OP code:" << endl;
	cout << "	For client:" << endl;
	cout << "		0: Generate key" << endl;
	cout << "		1: Road fordward and invert index" << endl;
	cout << "		2: Build search encrypted index and upload to server" << endl;
	cout << "		3: Generate search token and sent to server" << endl;
	cout << "		4: Generate add token and sent to server" << endl;
	cout << "		5: Generate delete token and sent to server" << endl;
	cout << "	For server:" << endl;
	cout << "		6: Receive search token and search" << endl;
	cout << "		7: Receive add token and add a file" << endl;
	cout << "		8: Receive a delete token and delete a file" << endl;
	cout << "	Ctrl + Z: Exit" << endl;
	cout << ">>";

	LARGE_INTEGER startTime, endTime, fre;
	double times;

	while (cin >> opcode)
	{
		QueryPerformanceFrequency(&fre); // 取得CPU頻率
		QueryPerformanceCounter(&startTime); // 取得開機到現在經過幾個CPU Cycle
		/* Program to Timing */
		switch (opcode)
		{
		case 0:

			break;

		case 1:

			cout << "Index loading complete." << endl;
			break;

		case 2:
			DSSE_obj.client_enc(pair_number);
			cout << "Searchable encrypted index building compllete." << endl;
			log_file << "Client: searchable encryption index building and upload to server" << endl;
			break;

		case 3:
			cout << "Enter a keyword you want to search: " << endl << ">>";
			cin >> keyword;
			DSSE_obj.client_srch_token(keyword, &F_k1_w, &G_k2_w, &P_k3_w);
			cout << "Generate a search token for keyword: " << keyword << endl;
			log_file << "Client: search token generation" << endl;
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
			log_file << "Server: search opreation" << endl;
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
		/* Program to Timing */
		QueryPerformanceCounter(&endTime); // 取得開機到程式執行完成經過幾個CPU Cycle
		times = ((double)endTime.QuadPart - (double)startTime.QuadPart) / fre.QuadPart;
		cout << fixed << setprecision(3) << "Processing time: " << times << 's' << endl << endl;
		log_file << fixed << setprecision(3) << "Processing time: " << times << 's' << endl << endl;

		cout << endl << "Enter OP code:" << endl;
		cout << "	For client:" << endl;
		cout << "		0: Generate key" << endl;
		cout << "		1: Road fordward and invert index" << endl;
		cout << "		2: Build search encrypted index and upload to server" << endl;
		cout << "		3: Generate search token and sent to server" << endl;
		cout << "		4: Generate add token and sent to server" << endl;
		cout << "		5: Generate delete token and sent to server" << endl;
		cout << "	For server:" << endl;
		cout << "		6: Receive search token and search" << endl;
		cout << "		7: Receive add token and add a file" << endl;
		cout << "		8: Receive a delete token and delete a file" << endl;
		cout << "	Ctrl + Z: Exit" << endl;
		cout << ">>";
	}

	log_file.close();

	return 0;
}