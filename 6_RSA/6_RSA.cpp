#include "..\third-party\src\cryptopp-CRYPTOPP_5_6_5\rsa.h"
#include "..\third-party\src\cryptopp-CRYPTOPP_5_6_5\osrng.h"
#include "..\third-party\src\cryptopp-CRYPTOPP_5_6_5\base64.h"
#include "MyFile.h"



class genKey
{
private:
	MyFile publicKey;
	MyFile privateKey;
	std::string path_publicKey = "..\\resources\\publicKey.txt";
	std::string path_privateKey = "..\\resources\\privateKey.txt";

public:
	void keyPairGener()
	{
		std::string strprivkey, strpubkey;

		CryptoPP::AutoSeededRandomPool rng;
		CryptoPP::InvertibleRSAFunction privkey;

		privkey.Initialize(rng, 1024);

		CryptoPP::Base64Encoder privkeysink(new CryptoPP::StringSink(strprivkey), false);
		privkey.DEREncode(privkeysink);
		privkeysink.MessageEnd();

		CryptoPP::RSAFunction pubkey(privkey);

		CryptoPP::Base64Encoder pubkeysink(new CryptoPP::StringSink(strpubkey), false);
		pubkey.DEREncode(pubkeysink);
		pubkeysink.MessageEnd();

		for (int i = 0; i < strpubkey.size(); i++)
		{
			publicKey.GetData().push_back(strpubkey.at(i));
		}

		for (int i = 0; i < strprivkey.size(); i++)
		{
			privateKey.GetData().push_back(strprivkey.at(i));
		}

		if (!publicKey.file_writing(path_publicKey))
		{
			std::cout << "Write error in publicKey.txt" << std::endl;
		}
		else
		{
			std::cout << "Public key generation successfully" << std::endl;
		}

		if (!privateKey.file_writing(path_privateKey))
		{
			std::cout << "Write error in privateKey.txt" << std::endl;
		}
		else
		{
			std::cout << "Private key generation successfully" << std::endl;
		}
		system("pause");
		system("cls");
	}
};

class RSA
{
private:
	MyFile plaintext;
	MyFile dec_plaintext;
	MyFile publicKey;
	MyFile privateKey;
	MyFile ciphertext;
	std::string path_plain = "..\\resources\\plaintext.txt";
	std::string path_dec_plain = "..\\resources\\dec_plain.txt";
	std::string path_publicKey = "..\\resources\\publicKey.txt";
	std::string path_privateKey = "..\\resources\\privateKey.txt";
	std::string path_cipher = "..\\resources\\cipher.txt";

public:
	RSA()
	{

	}

	void Encode()
	{
		int blockSize = 64;
		std::string plain = "";
		std::string pubKey = "";
		std::string cipher = "";
		CryptoPP::AutoSeededRandomPool rng;

		if (!plaintext.Open(path_plain))
		{
			std::cout << "File plaintext.txt not oppened" << std::endl;
		}
		else
		{
			std::cout << "File plaintext.txt oppened successful" << std::endl;
		}

		if (!publicKey.Open(path_publicKey))
		{
			std::cout << "File publicKey.txt not oppened" << std::endl;
		}
		else
		{
			std::cout << "File publicKey.txt oppened successful" << std::endl;
		}

		int fullSize = plaintext.GetData().size();
		while (fullSize % blockSize != 0) fullSize++;
		int s = plaintext.GetData().size();
		plaintext.GetData().resize(fullSize);

		for (int i = s; i < fullSize; i++)
		{
			plaintext.GetData().at(i) = 0;
		}

		for (int i = 0; i < publicKey.GetData().size(); i++)
		{
			pubKey += publicKey.GetData().at(i);
		}

		CryptoPP::StringSource pubString(pubKey, true, new CryptoPP::Base64Decoder);
		CryptoPP::RSAES_OAEP_SHA_Encryptor e(pubString);

		for (int j = 0; j < fullSize / blockSize; j++)
		{
			for (int i = 0; i < blockSize; i++)
			{
				plain += plaintext.GetData().at(blockSize*j + i);
			}
			CryptoPP::StringSource(plain, true, new CryptoPP::PK_EncryptorFilter(rng, e, new CryptoPP::StringSink(cipher)));

			for (int i = 0; i < cipher.size(); i++)
			{
				ciphertext.GetData().push_back(cipher.at(i));
			}
			plain = ""; cipher = "";
		}

		if (!ciphertext.file_writing(path_cipher))
		{
			std::cout << "Encryption error" << std::endl;
		}
		else
		{
			std::cout << "Encryption was successful" << std::endl;
		}
		system("pause");
		system("cls");
	}

	void Decode()
	{
		int blockSize = 128;
		std::string ciph = "";
		std::string privKey = "";
		std::string dec_plain = "";
		CryptoPP::AutoSeededRandomPool rng;

		if (!ciphertext.Open(path_cipher))
		{
			std::cout << "File cipher.txt not oppened" << std::endl;
		}
		else
		{
			std::cout << "File cipher.txt oppened successful" << std::endl;
		}

		if (!privateKey.Open(path_privateKey))
		{
			std::cout << "File privateKey.txt not oppened" << std::endl;
		}
		else
		{
			std::cout << "File privateKey.txt oppened successful" << std::endl;
		}

		for (int i = 0; i < privateKey.GetData().size(); i++)
		{
			privKey += privateKey.GetData().at(i);
		}

		CryptoPP::StringSource privString(privKey, true, new CryptoPP::Base64Decoder);
		CryptoPP::RSAES_OAEP_SHA_Decryptor d(privString);

		for (int j = 0; j < ciphertext.GetData().size() / blockSize; j++)
		{
			for (int i = 0; i < blockSize; i++)
			{
				ciph += ciphertext.GetData().at(j*blockSize + i);
			}
			CryptoPP::StringSource(ciph, true, new CryptoPP::PK_DecryptorFilter(rng, d, new CryptoPP::StringSink(dec_plain)));
			for (int i = 0; i < dec_plain.size(); i++)
			{
				dec_plaintext.GetData().push_back(dec_plain.at(i));
			}
			ciph = ""; dec_plain = "";
		}

		if (!dec_plaintext.file_writing(path_dec_plain))
		{
			std::cout << "Decryption error" << std::endl;
		}
		else
		{
			std::cout << "Decryption was successful" << std::endl;
		}
	}
};

int main()
{
	genKey k;
	k.keyPairGener();
	RSA object;
	object.Encode();
	object.Decode();
	system("pause");
}