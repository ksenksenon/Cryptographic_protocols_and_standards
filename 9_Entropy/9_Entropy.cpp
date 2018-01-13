#include <math.h>
#include "..\third-party\src\cryptopp-CRYPTOPP_5_6_5\sha.h"
#include "..\third-party\src\cryptopp-CRYPTOPP_5_6_5\osrng.h"
#include "..\third-party\src\cryptopp-CRYPTOPP_5_6_5\base64.h"
#include "..\third-party\src\cryptopp-CRYPTOPP_5_6_5\hex.h"
#include "MyFile.h"
#include "zip.h"


class Entropy
{
private:
	MyFile text;

public:
	double Entr8(std::string name)
	{
		if (!text.Open(name))
		{
			std::cout << "File not opened" << std::endl;
		}
		else
		{
			std::cout << "File opened successful" << std::endl;
		}

		unsigned int _8bitsbase[256];
		unsigned int size = text.GetData().size();
		double Prob = 0;
		double Entr = 0;
		for (unsigned int i = 0; i < 256; i++)
		{
			_8bitsbase[i] = 0;
		}
		uint8_t *mas = (uint8_t*)text.GetData().data();

		for (unsigned int i = 0; i < size; i++)
		{
			_8bitsbase[mas[i]]++;
		}
		for (unsigned int i = 0; i < 256; i++)
		{
			if (_8bitsbase[i] != 0)
			{
				Prob = (double)_8bitsbase[i] / size;
				Entr += Prob*log(Prob) / log(8);
			}
		}
		return -Entr;
	}

	double Entr16(std::string name)
	{
		if (!text.Open(name))
		{
			std::cout << "File not opened" << std::endl;
		}
		else
		{
			std::cout << "File opened successful" << std::endl;
		}
		unsigned int _16bitsbase[65536];
		unsigned int size = text.GetData().size() / 2;
		double Prob = 0;
		double Entr = 0;
		for (unsigned int i = 0; i < 65536; i++)
		{
			_16bitsbase[i] = 0;
		}
		uint16_t *mas = (uint16_t*)text.GetData().data();

		for (unsigned int i = 0; i < size; i++)
		{
			_16bitsbase[mas[i]]++;
		}
		for (unsigned int i = 0; i < 65536; i++)
		{
			if (_16bitsbase[i] != 0)
			{
				Prob = (double)_16bitsbase[i] / size;
				Entr += Prob*log(Prob) / log(16);
			}
		}
		return -Entr;
	}

	double Entr16Inter(std::string name)
	{
		if (!text.Open(name))
		{
			std::cout << "File not opened" << std::endl;
		}
		else
		{
			std::cout << "File opened successful" << std::endl;
		}
		unsigned int _16bitsbase[65536];
		unsigned int size = text.GetData().size() - 1;
		double Prob = 0;
		double Entr = 0;

		for (unsigned int i = 0; i < 65536; i++)
		{
			_16bitsbase[i] = 0;
		}

		uint16_t *current = (uint16_t*)text.GetData().data();
		uint8_t *sd = &text.GetData()[0];

		for (unsigned int i = 0; i < size; i++)
		{
			current = (uint16_t*)sd;
			_16bitsbase[*current]++;
			sd++;
		}

		for (unsigned int i = 0; i < 65536; i++)
		{
			if (_16bitsbase[i] != 0)
			{
				Prob = (double)_16bitsbase[i] / size;
				Entr += Prob*log(Prob) / log(16);
			}
		}
		return -Entr;
	}
};

class EntrHashing
{
private:
	MyFile plaintext;
	MyFile Hash_plaintextSHA;
	MyFile Hash_plaintextKs;

	std::string path_plain = "..\\resources\\plaintext.doc";
	std::string path_hash_plaintext = "..\\resources\\Hash_plaintextSHA.txt";
	std::string path_hash_plaintextKs = "..\\resources\\Hash_plaintextKs.txt";

	std::string sha256(std::string source)
	{
		std::string hash = "";
		CryptoPP::SHA256 sha256;
		CryptoPP::StringSource(source, true, new CryptoPP::HashFilter(sha256, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hash))));
		return hash;
	}

	std::string GenerHash(std::string source)
	{
		int hash_size = 32;
		std::vector <unsigned char> iv;
		std::string res = "";

		for (int i = 0; i < hash_size; i++)
		{
			char t = (25 + i) >> 2;
			iv.push_back(source.at(i%source.size())*t);
		}

		for (int i = 0; i < hash_size; i++)
		{
			res += ((iv.at(i)) ^ (i << 5));
		}

		if (source.size() > hash_size)
		{
			for (int i = 0; i < source.size(); i++)
			{
				res[i%hash_size] ^= source.at(i);
			}
		}
		else
			for (int i = 0; i < hash_size; i++)
			{
				res[i] ^= source.at(i%source.size());
			}
		return res;
	}


public:

	void ShaHash()
	{
		int blockSize = 32;
		std::string plain = "";
		if (!plaintext.Open(path_plain))
		{
			std::cout << "File plaintext.txt not oppened" << std::endl;
			return;
		}

		int fullSize = plaintext.GetData().size();
		while (fullSize % blockSize != 0) fullSize++;
		int s = plaintext.GetData().size();
		plaintext.GetData().resize(fullSize);

		for (int i = s; i < fullSize; i++)
		{
			plaintext.GetData().at(i) = 0;
		}

		for (int j = 0; j < fullSize / blockSize; j++)
		{
			for (int i = 0; i < blockSize; i++)
			{
				plain += plaintext.GetData().at(blockSize*j + i) + j;
			}
			std::string str = sha256(plain);

			for (int i = 0; i < str.size(); i += 2)
			{
				unsigned char temp = ((unsigned char)str[i] << 4) + (unsigned char)str[i + 1];
				Hash_plaintextSHA.GetData().push_back(temp);
			}
			plain = "";
		}

		Hash_plaintextSHA.file_writing(path_hash_plaintext);
	}
	void KsHash()
	{
		int blockSize = 32;
		std::string plain = "";
		if (!plaintext.Open(path_plain))
		{
			std::cout << "File plaintext.txt not oppened" << std::endl;
			return;
		}

		int fullSize = plaintext.GetData().size();
		while (fullSize % blockSize != 0) fullSize++;
		int s = plaintext.GetData().size();
		plaintext.GetData().resize(fullSize);

		for (int i = s; i < fullSize; i++)
		{
			plaintext.GetData().at(i) = 0;
		}

		for (int j = 0; j < fullSize / blockSize; j++)
		{
			for (int i = 0; i < blockSize; i++)
			{
				plain += plaintext.GetData().at(blockSize*j + i) + j;
			}

			std::string str = GenerHash(plain);

			for (int i = 0; i < str.size(); i++)
			{
				Hash_plaintextKs.GetData().push_back(str[i]);
			}
			plain = "";
		}
		Hash_plaintextKs.file_writing(path_hash_plaintextKs);
	}
};

void FileZip(std::string zip, std::string file, std::string path)
{
	TCHAR *zip_t = new TCHAR[zip.size() + 1];
	zip_t[zip.size()] = 0;
	std::copy(zip.begin(), zip.end(), zip_t);

	TCHAR *file_t = new TCHAR[file.size() + 1];
	file_t[file.size()] = 0;
	std::copy(file.begin(), file.end(), file_t);

	TCHAR *path_t = new TCHAR[path.size() + 1];
	path_t[path.size()] = 0;
	std::copy(path.begin(), path.end(), path_t);

	HZIP hz = CreateZip(zip_t, 0);
	ZipAdd(hz, file_t, path_t);
	CloseZip(hz);
}

void main()
{
	MyFile text;
	MyFile zip;

	std::string path_plain = "..\\resources\\plaintext.doc";
	std::string path_hash_plaintext = "..\\resources\\Hash_plaintextSHA.txt";
	std::string path_hash_plaintextKs = "..\\resources\\Hash_plaintextKs.txt";

	std::string path_plain_zip = "..\\resources\\plain.zip";
	std::string path_hash_plaintext_zip = "..\\resources\\sha.zip";
	std::string path_hash_plaintextKs_zip = "..\\resources\\ks.zip";

	EntrHashing ob1;
	ob1.ShaHash();
	ob1.KsHash();

	FileZip(path_plain_zip, "plaintext.doc", path_plain);
	FileZip(path_hash_plaintext_zip, "Hash_plaintextSHA.txt", path_hash_plaintext);
	FileZip(path_hash_plaintextKs_zip, "Hash_plaintextKs.txt", path_hash_plaintextKs);

	Entropy object;
	bool flag = true;
	int tmp = 0;
	while (flag)
	{
		std::cout << "Please select mode:" << std::endl;
		std::cout << "1) Entropy plaintext" << std::endl;
		std::cout << "2) Entropy text hashed with SHA-256" << std::endl;
		std::cout << "3) Entropy text hashed with KsHash" << std::endl;
		std::cout << "4) Zip plaintext" << std::endl;
		std::cout << "5) Zip SHA-256" << std::endl;
		std::cout << "6) Zip my hash" << std::endl;
		int mode = 0;
		std::cin >> mode;
		if (mode == 1)
		{
			std::cout << "Please select type of entropy:" << std::endl;
			std::cout << "1) 8 bit" << std::endl;
			std::cout << "2) 16 bit" << std::endl;
			std::cout << "3) 16 bit with intersection" << std::endl;
			int mode_en = 0;
			std::cin >> mode_en;
			if (mode_en == 1)
			{
				std::cout << "8 bit entropy for plaintext: " << object.Entr8(path_plain) << std::endl;
			}
			else
				if (mode_en == 2)
				{
					std::cout << "16 bit entropy for plaintext: " << object.Entr16(path_plain) << std::endl;
				}
				else
					if (mode_en == 3)
					{
						std::cout << "16 bit entropy with intersection for plaintext: " << object.Entr16Inter(path_plain) << std::endl;
					}
					else { std::cout << "Error" << std::endl; flag = false; }

					system("pause");
					system("cls");
		}
		else
			if (mode == 2)
			{
				std::cout << "Please select type of entropy:" << std::endl;
				std::cout << "1) 8 bit" << std::endl;
				std::cout << "2) 16 bit" << std::endl;
				std::cout << "3) 16 bit with intersection" << std::endl;
				int mode_en = 0;
				std::cin >> mode_en;
				if (mode_en == 1)
				{
					std::cout << "8 bit entropy for SHA hash: " << object.Entr8(path_hash_plaintext) << std::endl;
				}
				else
					if (mode_en == 2)
					{
						std::cout << "16 bit entropy for SHA hash: " << object.Entr16(path_hash_plaintext) << std::endl;
					}
					else
						if (mode_en == 3)
						{
							std::cout << "16 bit entropy with intersection for SHA hash: " << object.Entr16Inter(path_hash_plaintext) << std::endl;
						}
						else { std::cout << "Error" << std::endl; flag = false; }

						system("pause");
						system("cls");
			}
			else
				if (mode == 3)
				{
					std::cout << "Please select type of entropy:" << std::endl;
					std::cout << "1) 8 bit" << std::endl;
					std::cout << "2) 16 bit" << std::endl;
					std::cout << "3) 16 bit with intersection" << std::endl;
					int mode_en = 0;
					std::cin >> mode_en;
					if (mode_en == 1)
					{
						std::cout << "8 bit entropy for my hash: " << object.Entr8(path_hash_plaintextKs) << std::endl;
					}
					else
						if (mode_en == 2)
						{
							std::cout << "16 bit entropy for my hash: " << object.Entr16(path_hash_plaintextKs) << std::endl;
						}
						else
							if (mode_en == 3)
							{
								std::cout << "16 bit entropy with intersection for my hash: " << object.Entr16Inter(path_hash_plaintextKs) << std::endl;
							}
							else { std::cout << "Error" << std::endl; flag = false; }

							system("pause");
							system("cls");
				}
				else
					if (mode == 4)
					{
						text.Open(path_plain); zip.Open(path_plain_zip);
						double st = (double)text.GetData().size() / zip.GetData().size();
						std::cout << "Size before: " << text.GetData().size() << std::endl;
						std::cout << "Size after: " << zip.GetData().size() << std::endl;
						std::cout << "Data compression ratio for plaintext: " << st << std::endl;
						system("pause");
						system("cls");
					}
					else
						if (mode == 5)
						{
							text.Open(path_hash_plaintext); zip.Open(path_hash_plaintext_zip);
							double st = (double)text.GetData().size() / zip.GetData().size();
							std::cout << "Size before: " << text.GetData().size() << std::endl;
							std::cout << "Size after: " << zip.GetData().size() << std::endl;
							std::cout << "Data compression ratio for SHA-256: " << st << std::endl;
							system("pause");
							system("cls");
						}
						else
							if (mode == 6)
							{
								text.Open(path_hash_plaintextKs); zip.Open(path_hash_plaintextKs_zip);
								double st = (double)text.GetData().size() / zip.GetData().size();
								std::cout << "Size before: " << text.GetData().size() << std::endl;
								std::cout << "Size after: " << zip.GetData().size() << std::endl;
								std::cout << "Data compression ratio for My Hash: " << st << std::endl;
								system("pause");
								system("cls");
							}
							else
							{
								std::cout << "Error" << std::endl; flag = false;
								system("pause");
								system("cls");
							}
		std::cout << "Do you want to continue? 1 - yes/ 2 - no : ";
		std::cin >> tmp;
		if (tmp == 1) flag = true;
		else if (tmp == 2) flag = false;
		else
		{
			std::cout << "Error" << std::endl; flag = false;
		}
	}
	system("pause");
}