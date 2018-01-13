#include <windows.h>
#include <tlhelp32.h>
#include <map>
#include <iostream>
#include <string>
#include <algorithm>
#include <thread>
#include <iterator>
#include <conio.h>


void ProcessList(HANDLE CONST hStdOut, std::map <int, std::string> &myMap)
{
	PROCESSENTRY32 peProcessEntry;
	HANDLE CONST hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot)
	{
		return;
	}
	peProcessEntry.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hSnapshot, &peProcessEntry);
	char temp[50];
	do
	{
		wcstombs(temp, peProcessEntry.szExeFile, sizeof(peProcessEntry.szExeFile));
		std::string conv_name = temp;
		myMap.insert(std::pair <int, std::string>(peProcessEntry.th32ProcessID, conv_name));
	} while (Process32Next(hSnapshot, &peProcessEntry));
	CloseHandle(hSnapshot);
}

int main(int argc, char* argv[])
{
	std::map <int, std::string> current;
	std::map <int, std::string> next;
	std::map <int, std::string> result;

	HANDLE CONST hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	ProcessList(hStdOut, current);
	bool flag = false;
	std::cout << "To stop press any key" << std::endl;
	while (!flag)
	{
		if (_kbhit())
		{
			flag = true;
		}
		Sleep(50);
		ProcessList(hStdOut, next);
		std::set_difference(current.begin(), current.end(), next.begin(), next.end(),
			std::inserter(result, result.begin()));
		if (!result.empty())
		{
			for (auto item : result)
			{
				std::cout << "Closed process: " << item.first << " " << item.second << "\n";
			}
		}
		result.clear();

		std::set_difference(next.begin(), next.end(), current.begin(), current.end(),
			std::inserter(result, result.begin()));
		if (!result.empty())
		{
			for (auto item : result)
			{
				std::cout << "Opened process: " << item.first << " " << item.second << "\n";
			}
		}
		result.clear();
		current = next;
		next.clear();
	}
	system("pause");
	return 0;
}