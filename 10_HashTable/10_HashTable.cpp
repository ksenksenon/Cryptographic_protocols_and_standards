#include <time.h>
#include "..\third-party\src\cryptopp-CRYPTOPP_5_6_5\sha.h"
#include "..\third-party\src\cryptopp-CRYPTOPP_5_6_5\osrng.h"
#include "..\third-party\src\cryptopp-CRYPTOPP_5_6_5\base64.h"
#include "..\third-party\src\cryptopp-CRYPTOPP_5_6_5\hex.h"
#include "MyFile.h"

class Attributes
{
private:

	std::string path_key;

	std::string ftCreationTime;
	std::string ftLastAccessTime;
	std::string ftLastWriteTime;
	std::string FileSize;
	std::string cAlternateFileName;
	std::string archive;
	std::string compressed;
	std::string encrypted;
	std::string hidden;
	std::string offline;
public:

	std::string ReturnPath()
	{
		return path_key;
	}

	Attributes()
	{
	}

	Attributes(std::string path_key, std::string ftCreationTime, std::string ftLastAccessTime, std::string ftLastWriteTime,
		std::string FileSize, std::string cAlternateFileName, std::string archive, std::string compressed, std::string encrypted, std::string hidden, std::string offline)
	{
		this->path_key = path_key;

		this->ftCreationTime = ftCreationTime;
		this->ftLastAccessTime = ftLastAccessTime;
		this->ftLastWriteTime = ftLastWriteTime;
		this->FileSize = FileSize;
		this->cAlternateFileName = cAlternateFileName;
		this->archive = archive;
		this->compressed = compressed;
		this->encrypted = encrypted;
		this->hidden = hidden;
		this->offline = offline;
	}

	~Attributes()
	{

	}
};

uint16_t KsHash(std::string source)
{
	const int hash_size = 32;
	std::vector <byte> plain;
	std::vector <byte> iv;
	std::vector <byte> hashcode;
	hashcode.resize(32);

	for (int i = 0; i < source.size(); i++)
	{
		plain.push_back(source[i]);
	}

	for (unsigned int i = 0; i < hash_size; i++)
	{
		char t = (25 + i) >> 2;
		iv.push_back(plain[i % plain.size()] * t);
	}

	for (int i = 0; i < hash_size; i++)
	{
		hashcode[i] = ((iv.at(i)) ^ (i << 5));
	}

	if (plain.size() > hash_size)
	{
		for (int i = 0; i < plain.size(); i++)
		{
			hashcode[i%hash_size] ^= plain.at(i);
		}
	}
	else
		for (int i = 0; i < hash_size; i++)
		{
			hashcode[i] ^= plain[i % plain.size()];
		}

	uint16_t *result = (uint16_t*)hashcode.data();
	return *result;
}

uint16_t SHA256(std::string text)
{
	std::string source;
	std::string hash;
	std::vector <byte> hashcode;

	for (int i = 0; i < text.size(); i++)
	{
		source += text[i];
	}
	CryptoPP::SHA256 sha256;
	CryptoPP::StringSource(source, true, new CryptoPP::HashFilter(sha256, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hash))));
	for (int i = 0; i < hash.size(); i += 2)
	{
		byte temp = ((byte)hash[i] << 4) + (byte)hash[i + 1];
		hashcode.push_back(temp);
	}
	uint16_t *result = (uint16_t*)hashcode.data();
	return *result;
}

bool CreateTable(std::vector<std::vector<Attributes>> &MyTable, std::string directory_path, int func, int &count_elem, int &rows, double &alpha_max)
{
	WIN32_FIND_DATAA FindFileData;
	HANDLE hFind;

	std::string _path = directory_path + "\\*";
	hFind = FindFirstFileA(_path.c_str(), &FindFileData);
	FindNextFileA(hFind, &FindFileData);
	bool rebuild = false;
	if (FindNextFileA(hFind, &FindFileData))
	{
		if (hFind != INVALID_HANDLE_VALUE)
		{

			do
			{
				count_elem++;
				std::string archive = "Not archive";
				std::string compressed = "Not compressed";
				std::string encrypted = "Not encrypted";
				std::string hidden = "Not hidden";
				std::string offline = "Not offline";

				bool pars = true;
				char buffer[MAX_PATH];

				if (strlen(&FindFileData.cFileName[0]) == 1 && strchr(FindFileData.cFileName, '.') != NULL) pars = false;
				if (strlen(&FindFileData.cFileName[0]) == 2 && strchr(FindFileData.cFileName, '..') != NULL) pars = false;

				if (FindFileData.dwFileAttributes && FILE_ATTRIBUTE_DIRECTORY)
				{
					if (pars)
					{
						_path = directory_path + "\\" + std::string(&FindFileData.cFileName[0]);
						CreateTable(MyTable, _path, func, count_elem, rows, alpha_max);
					}
				}

				SYSTEMTIME Time;
				FileTimeToSystemTime(&FindFileData.ftCreationTime, &Time);
				sprintf(buffer, "%d-%02d-%02d %02d:%02d:%02d", Time.wYear, Time.wMonth, Time.wDay, Time.wHour, Time.wMinute, Time.wSecond);
				std::string ftCreationTime = buffer;

				FileTimeToSystemTime(&FindFileData.ftLastAccessTime, &Time);
				sprintf(buffer, "%d-%02d-%02d %02d:%02d:%02d", Time.wYear, Time.wMonth, Time.wDay, Time.wHour, Time.wMinute, Time.wSecond);
				std::string ftLastAccessTime = buffer;

				FileTimeToSystemTime(&FindFileData.ftLastWriteTime, &Time);
				sprintf(buffer, "%d-%02d-%02d %02d:%02d:%02d", Time.wYear, Time.wMonth, Time.wDay, Time.wHour, Time.wMinute, Time.wSecond);
				std::string ftLastWriteTime = buffer;

				std::stringstream ss;
				ss << (FindFileData.nFileSizeHigh * (MAXDWORD + 1)) + FindFileData.nFileSizeLow;
				std::string FileSize = ss.str();

				sprintf(buffer, "%s", FindFileData.cAlternateFileName);
				std::string AlternateFileName = buffer;

				if (FindFileData.dwFileAttributes && FILE_ATTRIBUTE_ARCHIVE)
				{
					archive = "Archive";
				}

				if (FindFileData.dwFileAttributes && FILE_ATTRIBUTE_COMPRESSED)
				{
					compressed = "Compressed";
				}

				if (FindFileData.dwFileAttributes && FILE_ATTRIBUTE_ENCRYPTED)
				{
					encrypted = "Encrypted";
				}

				if (FindFileData.dwFileAttributes && FILE_ATTRIBUTE_HIDDEN)
				{
					hidden = "Hidden";
				}

				if (FindFileData.dwFileAttributes && FILE_ATTRIBUTE_OFFLINE)
				{
					offline = "Offline";
				}

				Attributes *file_info = new Attributes(_path, ftCreationTime, ftLastAccessTime, ftLastWriteTime, FileSize, AlternateFileName,
					archive, compressed, encrypted, hidden, offline);

				if (func == 1)
				{
					//std::cout << "Hashcode: "<<KsHash(_path)<< std::endl;
					if (MyTable[KsHash(_path)].empty())
					{
						rows++;
					}
					MyTable[KsHash(_path)].push_back(*file_info);
				}
				else
					if (func == 2)
					{
						//std::cout << "Hashcode: " << SHA256(_path) << std::endl;
						if (MyTable[SHA256(_path)].empty())
						{
							rows++;
						}
						MyTable[SHA256(_path)].push_back(*file_info);
					}
				if (count_elem % 50 == 0)
				{
					system("cls");
					std::cout << "Alpha maximum: " << alpha_max;
					if (func == 1)
					{
						std::cout << "\nCreating hash-table with KsHash function in process" << std::endl;
					}
					else if (func == 2)
					{
						std::cout << "\nCreating hash-table with SHA-256 function in process" << std::endl;
					}
					std::cout << "Number of objects: " << count_elem << "\nRows: " << rows << "\nAlpha average: " << (double)count_elem / rows << std::endl;
				}

				if (((double)count_elem / rows) >= alpha_max)
				{
					rebuild = true;
					return rebuild;
				}
			} while (FindNextFileA(hFind, &FindFileData));
			FindClose(hFind);
			return rebuild;
		}
	}

}

void TabWrite(std::vector<std::vector<Attributes>> &MyTable, std::string name)
{
	FILE * _file;
	_file = fopen(name.c_str(), "w");
	for (int i = 0; i < MyTable.size(); i++)
	{
		if (!MyTable.at(i).empty())
		{
			fprintf(_file, "Hash: %d\n", i);
			for each (Attributes obj in MyTable.at(i))
			{
				fprintf(_file, "%s\n", obj.ReturnPath().c_str());
			}
			fprintf(_file, "\n");
		}
	}
	fclose(_file);
}


void main()
{
	std::vector<std::vector<Attributes>> NewTable;
	std::string directory = "C:\\Windows\\System32";
	std::string res_path = "..\\resources\\res_hash.txt";

	double alpha_max = 0;
	int mode = 0;
	int count_elem = 0;
	int rows = 0;
	bool flag = true;

	while (flag)
	{

		bool build = false;
		int counter = 0;
		system("cls");
		std::string answer;
		std::cout << "Please select maximum alpha for table: " << std::endl;
		std::cin >> alpha_max;
		std::cout << "Please select hash-function:" << std::endl;
		std::cout << "1) KsHash" << std::endl;
		std::cout << "2) SHA-256" << std::endl;
		std::cin >> mode;

		while (counter < 2 && !build)
		{
			counter++;
			int count_elem = 0;
			int rows = 0;
			int start = 0;
			int stop = 0;
			NewTable.clear();
			NewTable.resize(65536);

			start = clock();

			if (CreateTable(NewTable, directory, mode, count_elem, rows, alpha_max))
			{
				build = false;
				stop = clock();
				system("cls");
				std::cout << "Alpha average = " << (double)count_elem / rows << " >= alpha maximum";
				std::cout << "\nNeed to rebuild the hash-table with other hash-function";
				std::cout << "\nPress any key to continue";
				getch();
				if (mode == 1) mode = 2; else mode = 1;
			}
			else
			{
				build = true;
				stop = clock();
				system("cls");
				std::cout << "Hash-table was created";
				std::cout << "\nNumber of objects in hash-table: " << count_elem;
				std::cout << "\nRows: " << rows;
				std::cout << "\nAlpha average: " << (double)count_elem / rows;
				std::cout << "\nTime = " << (stop - start) / 1000.0 << " seconds" << std::endl;

				std::cout << "Do you want to write hash-table to file? Y/N" << std::endl;
				std::cin >> answer;
				if (answer == "Y")
				{
					TabWrite(NewTable, res_path);
					std::cout << "Result will be save in res_hash.txt" << std::endl;
				}
				else
					std::cout << "Ok :(" << std::endl;
			}
		}
		if (counter >= 2 && !build)
		{
			system("cls");
			std::cout << "Please change the alpha maximum. Both functions don't give you a very good result" << std::endl;
		}

		std::cout << "Do you want to continue? Y/N" << std::endl;
		std::cin >> answer;
		if (answer == "Y") flag = true; else flag = false;
	}
	system("pause");
}

