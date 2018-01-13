#include <iostream> 
#include <string> 

void cipher(std::string &s)
{
	for (int i = 0; i < s.size(); i++)
	{
		s[i] += i;
		s[i] ^= i;
		s[i] %= 26;
		s[i] += 65;
	}
}

int main()
{
	std::string plain;
	std::cout << "Enter your name" << std::endl;
	std::cin >> plain;
	cipher(plain);
	std::cout << plain << std::endl;
	system("pause");
}