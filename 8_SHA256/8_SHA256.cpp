#include "..\third-party\src\cryptopp-CRYPTOPP_5_6_5\sha.h"
#include "..\third-party\src\cryptopp-CRYPTOPP_5_6_5\osrng.h"
#include "..\third-party\src\cryptopp-CRYPTOPP_5_6_5\base64.h"
#include "..\third-party\src\cryptopp-CRYPTOPP_5_6_5\hex.h"
#include "MyFile.h"


class MyHash
{
private:
	MyFile plaintext;
	MyFile hashcode;
	std::string path_plain = "..\\resources\\plaintext.txt";
	std::string path_hash256 = "..\\resources\\hash256.txt";

public:

	void sha256()
	{
		if (!plaintext.Open(path_plain))
		{
			std::cout << "File plain.doc not oppened" << std::endl;
		}
		else
		{
			std::cout << "File plain.doc oppened successful" << std::endl;
		}
		std::string source = "";
		std::string hash = "";
		for (int i = 0; i < plaintext.GetData().size(); i++)
		{
			source += plaintext.GetData().at(i);
		}
		CryptoPP::SHA256 sha256;
		CryptoPP::StringSource(source, true, new CryptoPP::HashFilter(sha256, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hash))));
		for (int i = 0; i < hash.size(); i += 2)
		{
			unsigned char temp = ((unsigned char)hash[i] << 4) + (unsigned char)hash[i + 1];
			hashcode.GetData().push_back(temp);
		}
		if (!hashcode.file_writing(path_hash256))
		{
			std::cout << "Write error in hash256.txt" << std::endl;
		}
		else
		{
			std::cout << "SHA 256 generation successfully" << std::endl;
		}
	}
};

int main()
{
	MyHash object;
	object.sha256();
	system("pause");
}