#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <ctime>
#include <stdio.h>
#include <conio.h>
#include <windows.h>

#pragma warning(disable : 4996)
#define _CRT_SECURE_NO_WARNINGS

class MyFile
{
private:
	std::vector <unsigned char> _data;
	FILE* _file;

public:
	MyFile()
		: _file(NULL)
	{

	}

	std::vector <unsigned char> &GetData() { return _data; }

	bool Open(std::string &name)
	{
		_file = fopen(name.c_str(), "rb");

		if (_file != NULL)
		{
			fseek(_file, 0, SEEK_END);
			int size = ftell(_file);
			rewind(_file);
			_data.resize(size);
			fread(_data.data(), 1, size, _file);
			fclose(_file);
		}
		return !_data.empty();
	}

	bool file_writing(std::string &name)
	{
		_file = fopen(name.c_str(), "wb");
		bool flag = fwrite(_data.data(), 1, _data.size(), _file);
		fclose(_file);
		return !(flag == false);
	}
};
