#include "MyFile.h"


class MyHash
{
private:
	MyFile plaintext;
	MyFile hashcode;
	std::string path_plain = "..\\resources\\plaintext.doc";
	std::string path_hash = "..\\resources\\hash.txt";

public:
	void GenerHash()
	{
		int hash_size = 256;
		std::vector<unsigned char> iv;

		if (!plaintext.Open(path_plain))
		{
			std::cout << "File plaintext.txt not oppened" << std::endl;
		}
		else
		{
			std::cout << "File plaintext.txt oppened successful" << std::endl;
		}

		for (int i = 0; i < hash_size; i++)
		{
			char t = (25 + i) >> 2;
			iv.push_back(plaintext.GetData().at(i%plaintext.GetData().size())*t);
		}


		for (int i = 0; i < hash_size; i++)
		{
			hashcode.GetData().push_back((iv.at(i)) ^ (i << 5));
		}

		if (plaintext.GetData().size() > hash_size)
		{
			for (int i = 0; i < plaintext.GetData().size(); i++)
			{
				hashcode.GetData()[i%hash_size] ^= plaintext.GetData().at(i);
			}
		}
		else
			for (int i = 0; i < hash_size; i++)
			{
				hashcode.GetData()[i] ^= plaintext.GetData().at(i%plaintext.GetData().size());
			}

		if (!hashcode.file_writing(path_hash))
		{
			std::cout << "Write error in hash.txt" << std::endl;
		}
		else
		{
			std::cout << "Hash generation successfully" << std::endl;
		}

	}

};

int main()
{
	MyHash object;
	object.GenerHash();
	system("pause");
}