#include "MyFile.h"


class OneTimePad
{
private:
	MyFile plaintext;
	MyFile dec_plaintext;
	MyFile key;
	MyFile ciphertext;
	std::string path_plain = "..\\resources\\plain.doc";
	std::string path_dec_plain = "..\\resources\\dec_plain.doc";
	std::string path_key = "..\\resources\\key.doc";
	std::string path_cipher = "..\\resources\\cipher.doc";

public:
	OneTimePad()
	{

	}

	void ciph()
	{
		if (!plaintext.Open(path_plain))
		{
			std::cout << "File plain.doc not oppened" << std::endl;
			return;
		}

		for (int i = 0; i < plaintext.GetData().size(); i++)
		{
			key.GetData().push_back((char)rand() % 256);
		}

		if (!key.file_writing(path_key))
		{
			std::cout << "Write error file key.doc" << std::endl;

		}
		else
		{
			std::cout << "Key generation successful" << std::endl;
		}

		if (!key.Open(path_key))
		{
			std::cout << "File key.doc not oppened" << std::endl;
			return;
		}

		if (plaintext.GetData().size() != key.GetData().size())
		{
			std::cout << "Error! Source file and key have a different size";

		}
		else
		{
			for (int i = 0; i < plaintext.GetData().size(); i++)
			{
				ciphertext.GetData().push_back(plaintext.GetData().at(i) ^ key.GetData().at(i));
			}

			if (!ciphertext.file_writing(path_cipher))
			{
				std::cout << "Write error in cipher.doc" << std::endl;
			}
			else
			{
				std::cout << "Encryption successfully" << std::endl;
			}
			
		}

	}

	void deciph()
	{
		if (!ciphertext.Open(path_cipher))
		{
			std::cout << "File cipher.doc not oppened" << std::endl;
			return;
		}

		if (!key.Open(path_key))
		{
			std::cout << "File key.doc not oppened" << std::endl;
			return;
		}

		if (ciphertext.GetData().size() != key.GetData().size())
		{
			std::cout << "Error! Encrypted file and key have a different size";

		}
		else
		{
			for (int i = 0; i < ciphertext.GetData().size(); i++)
			{
				dec_plaintext.GetData().push_back(ciphertext.GetData().at(i) ^ key.GetData().at(i));
			}

			if (!dec_plaintext.file_writing(path_dec_plain))
			{
				std::cout << "Write error in dec_plain.doc" << std::endl;
			}
			else
			{
				std::cout << "Decryption successfully" << std::endl;
			}
			
		}
	}
};

int main()
{
	OneTimePad object;
	std::cout << "Please select the operating mode: 1 - encryption, 2 - decryption" << std::endl;
	int mode = 0;
	std::cin >> mode;
	if (mode == 1)
	{
		std::cout << "Encryption in progress" << std::endl;
		object.ciph();
	}
	else if (mode == 2)
	{
		std::cout << "Decryption in progress" << std::endl;
		object.deciph();
	}
	system("pause");
}