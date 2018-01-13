#include "MyFile.h"

class genKey
{
private:
	MyFile key;
	std::string path_key = "..\\resources\\key.doc";

public:
	void keyGener(int key_size)
	{
		for (int i = 0; i < key_size; i++)
		{
			key.GetData().push_back((unsigned char)rand() % 256);
		}
		if (!key.file_writing(path_key))
		{
			std::cout << "Write error in key.doc" << std::endl;
		}
		else
		{
			std::cout << "Key generation successfully" << std::endl;
			system("pause");
		}
		system("cls");
	}
};

class RC4
{
private:
	MyFile plaintext;
	MyFile ciphertext;
	MyFile key;
	MyFile dec_plain;
	std::string path_plain = "..\\resources\\plain.doc";
	std::string path_key = "..\\resources\\key.doc";
	std::string path_cipher = "..\\resources\\cipher.doc";
	std::string dec_path = "..\\resources\\dec_plain.doc";

	unsigned char s[256];
	int i = 0;
	int j = 0;

	void InitialS()
	{
		key.Open(path_key);
		for (i = 0; i < 256; i++)
		{
			s[i] = (unsigned char)i;
		}
		j = 0;
		for (i = 0; i < 256; i++)
		{
			j = (j + s[i] + key.GetData()[i % key.GetData().size()]) % 256;
			unsigned char tmp = s[i];
			s[i] = s[j];
			s[j] = tmp;
		}
		i = 0; j = 0;
	}

	unsigned char keyItem()
	{
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;
		unsigned char tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
		return s[(s[i] + s[j]) % 256];
	}

public:
	RC4()
	{
	}

	void Encode()
	{
		InitialS();
		if (!plaintext.Open(path_plain))
		{
			std::cout << "File plain.doc not oppened" << std::endl;
			return;
		}

		for (int m = 0; m < plaintext.GetData().size(); m++)
		{
			ciphertext.GetData().push_back((plaintext.GetData()[m] ^ keyItem()));
		}
		if (!ciphertext.file_writing(path_cipher))
		{
			std::cout << "Write error in cipher.doc" << std::endl;
		}
		else
		{
			std::cout << "Encryption to cipher.doc successfully" << std::endl;
			system("pause");
		}
		system("cls");
	}
	void Decode()
	{
		InitialS();
		if (!ciphertext.Open(path_cipher))
		{
			std::cout << "File cipher.doc not oppened" << std::endl;
			return;
		}

		for (int m = 0; m < ciphertext.GetData().size(); m++)
		{
			dec_plain.GetData().push_back((ciphertext.GetData()[m] ^ keyItem()));
		}

		if (!dec_plain.file_writing(dec_path))
		{
			std::cout << "Write error in dec_plain.doc" << std::endl;
		}
		else
		{
			std::cout << "Decryption to dec_plain.doc successfully" << std::endl;
		}
	}
};

int main()
{
	std::cout << "Size of key: " << std::endl;
	int size;
	std::cin >> size;
	system("cls");
	genKey k;
	k.keyGener(size);
	RC4 object;
	std::cout << "Encryption in progress" << std::endl;
	object.Encode();
	std::cout << "Decryption in progress" << std::endl;
	object.Decode();
	system("pause");
}