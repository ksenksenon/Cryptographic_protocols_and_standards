#include "..\third-party\src\cryptopp-CRYPTOPP_5_6_5\aes.h"
#include "..\third-party\src\cryptopp-CRYPTOPP_5_6_5\modes.h"
#include "..\third-party\src\cryptopp-CRYPTOPP_5_6_5\osrng.h"
#include "MyFile.h"

class AES
{

private:
	MyFile plaintext;
	MyFile dec_plaintext;
	MyFile key;
	MyFile iv;
	MyFile ciphertext;
	std::string path_plain = "..\\resources\\plain.doc";
	std::string path_dec_plain = "..\\resources\\dec_plain.doc";
	std::string path_key = "..\\resources\\key.doc";
	std::string path_vect = "..\\resources\\vect.doc";
	std::string path_cipher = "..\\resources\\cipher.doc";

public:
	AES()
	{

	}

	void keyGenerate(byte * keyBytes)
	{
		CryptoPP::AutoSeededRandomPool rnd;
		rnd.GenerateBlock(keyBytes, CryptoPP::AES::DEFAULT_KEYLENGTH);
		for (int i = 0; i < CryptoPP::AES::DEFAULT_KEYLENGTH; i++)
		{
			key.GetData().push_back(keyBytes[i]);
		}
		if (!key.file_writing(path_key))
		{
			std::cout << "Write error file key.doc" << std::endl;
		}
		else
		{
			std::cout << "Key generation successful" << std::endl;
		}
	}

	void ivGenerate(byte * ivBytes)
	{
		CryptoPP::AutoSeededRandomPool rnd;
		rnd.GenerateBlock(ivBytes, CryptoPP::AES::BLOCKSIZE);
		for (int i = 0; i < CryptoPP::AES::BLOCKSIZE; i++)
		{
			iv.GetData().push_back(ivBytes[i]);
		}

		if (!iv.file_writing(path_vect))
		{
			std::cout << "Write error file vect.doc" << std::endl;
		}
		else
		{
			std::cout << "Vector generation successful" << std::endl;
		}
	}

	int Encryption()
	{
		std::cout << "Select one of the encryption modes:" << std::endl;
		std::cout << "1) Electronic code book" << std::endl;
		std::cout << "2) Cipher block chaining" << std::endl;
		std::cout << "3) Cipher feed back" << std::endl;
		std::cout << "4) Output feed back" << std::endl;
		std::cout << "5) Counter mode" << std::endl;
		int mode;
		std::cin >> mode;

		if (!plaintext.Open(path_plain))
		{
			std::cout << "File plain.doc not oppened" << std::endl;
		}
		else
		{
			std::cout << "File plain.doc oppened successful" << std::endl;
		}

		byte keyBytes[CryptoPP::AES::DEFAULT_KEYLENGTH];
		byte ivBytes[CryptoPP::AES::BLOCKSIZE];

		ciphertext.GetData().resize(plaintext.GetData().size() + CryptoPP::AES::BLOCKSIZE);
		CryptoPP::ArraySink cs(&ciphertext.GetData()[0], ciphertext.GetData().size());

		if (mode == 1)
		{
			std::cout << "Encryption in ECD mode in process" << std::endl;
			keyGenerate(keyBytes);
			CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption Enc;
			Enc.SetKey(keyBytes, sizeof(keyBytes));
			CryptoPP::ArraySource(plaintext.GetData().data(), plaintext.GetData().size(), true,
				new CryptoPP::StreamTransformationFilter(Enc, new CryptoPP::Redirector(cs)));
		}

		else if (mode == 2)
		{
			std::cout << "Encryption in CBC mode in process" << std::endl;
			keyGenerate(keyBytes); ivGenerate(ivBytes);
			CryptoPP::CBC_Mode< CryptoPP::AES>::Encryption Enc;
			Enc.SetKeyWithIV(keyBytes, sizeof(keyBytes), ivBytes);
			CryptoPP::ArraySource(plaintext.GetData().data(), plaintext.GetData().size(), true,
				new CryptoPP::StreamTransformationFilter(Enc, new CryptoPP::Redirector(cs)));
		}

		else if (mode == 3)
		{
			std::cout << "Encryption in CFB mode in process" << std::endl;
			keyGenerate(keyBytes); ivGenerate(ivBytes);
			CryptoPP::CFB_Mode< CryptoPP::AES>::Encryption Enc;
			Enc.SetKeyWithIV(keyBytes, sizeof(keyBytes), ivBytes);
			CryptoPP::ArraySource(plaintext.GetData().data(), plaintext.GetData().size(), true,
				new CryptoPP::StreamTransformationFilter(Enc, new CryptoPP::Redirector(cs)));
		}

		else if (mode == 4)
		{
			std::cout << "Encryption in OFB mode in process" << std::endl;
			keyGenerate(keyBytes); ivGenerate(ivBytes);
			CryptoPP::OFB_Mode< CryptoPP::AES>::Encryption Enc;
			Enc.SetKeyWithIV(keyBytes, sizeof(keyBytes), ivBytes);
			CryptoPP::ArraySource(plaintext.GetData().data(), plaintext.GetData().size(), true,
				new CryptoPP::StreamTransformationFilter(Enc, new CryptoPP::Redirector(cs)));
		}

		else if (mode == 5)
		{
			std::cout << "Encryption in CTR mode in process" << std::endl;
			keyGenerate(keyBytes); ivGenerate(ivBytes);
			CryptoPP::CTR_Mode< CryptoPP::AES>::Encryption Enc;
			Enc.SetKeyWithIV(keyBytes, sizeof(keyBytes), ivBytes);
			CryptoPP::ArraySource(plaintext.GetData().data(), plaintext.GetData().size(), true,
				new CryptoPP::StreamTransformationFilter(Enc, new CryptoPP::Redirector(cs)));
		}

		ciphertext.GetData().resize(cs.TotalPutLength());
		if (!ciphertext.file_writing(path_cipher))
		{
			std::cout << "Encryption error" << std::endl;
		}
		else
		{
			std::cout << "Encryption was successful" << std::endl;
		}
		return mode;
	}
	void keyGet(byte * randomKey)
	{
		if (!key.Open(path_key))
		{
			std::cout << "File key.doc not oppened" << std::endl;
			return;
		}
		for (int i = 0; i < CryptoPP::AES::DEFAULT_KEYLENGTH; i++)
		{
			randomKey[i] = key.GetData()[i];
		}
	}

	void ivGet(byte * randomIv)
	{
		if (!iv.Open(path_vect))
		{
			std::cout << "File vect.doc not oppened" << std::endl;
			return;
		}

		for (int i = 0; i < CryptoPP::AES::BLOCKSIZE; i++)
		{
			randomIv[i] = iv.GetData()[i];
		}
	}
	void Decryption(int mode)
	{
		byte randomKey[CryptoPP::AES::DEFAULT_KEYLENGTH];
		byte randomIv[CryptoPP::AES::BLOCKSIZE];

		if (!ciphertext.Open(path_cipher))
		{
			std::cout << "File cipher.doc not oppened" << std::endl;
			return;
		}
		else
		{
			std::cout << "File cipher.doc oppened successful" << std::endl;
		}
		dec_plaintext.GetData().resize(ciphertext.GetData().size() + CryptoPP::AES::BLOCKSIZE);

		CryptoPP::ArraySink ds(&dec_plaintext.GetData()[0], dec_plaintext.GetData().size());

		if (mode == 1)
		{
			keyGet(randomKey);
			CryptoPP::ECB_Mode< CryptoPP::AES>::Decryption Dec;
			Dec.SetKey(randomKey, sizeof(randomKey));
			CryptoPP::ArraySource(ciphertext.GetData().data(), ciphertext.GetData().size(), true,
				new CryptoPP::StreamTransformationFilter(Dec, new CryptoPP::Redirector(ds)));
		}

		else if (mode == 2)
		{
			keyGet(randomKey); ivGet(randomIv);
			CryptoPP::CBC_Mode< CryptoPP::AES>::Decryption Dec;
			Dec.SetKeyWithIV(randomKey, sizeof(randomKey), randomIv);
			CryptoPP::ArraySource(ciphertext.GetData().data(), ciphertext.GetData().size(), true,
				new CryptoPP::StreamTransformationFilter(Dec, new CryptoPP::Redirector(ds)));
		}

		else if (mode == 3)
		{
			keyGet(randomKey); ivGet(randomIv);
			CryptoPP::CFB_Mode< CryptoPP::AES>::Decryption Dec;
			Dec.SetKeyWithIV(randomKey, sizeof(randomKey), randomIv);
			CryptoPP::ArraySource(ciphertext.GetData().data(), ciphertext.GetData().size(), true,
				new CryptoPP::StreamTransformationFilter(Dec, new CryptoPP::Redirector(ds)));
		}

		else if (mode == 4)
		{
			keyGet(randomKey); ivGet(randomIv);
			CryptoPP::OFB_Mode< CryptoPP::AES>::Decryption Dec;
			Dec.SetKeyWithIV(randomKey, sizeof(randomKey), randomIv);
			CryptoPP::ArraySource(ciphertext.GetData().data(), ciphertext.GetData().size(), true,
				new CryptoPP::StreamTransformationFilter(Dec, new CryptoPP::Redirector(ds)));
		}

		else if (mode == 5)
		{
			keyGet(randomKey); ivGet(randomIv);
			CryptoPP::CTR_Mode< CryptoPP::AES>::Decryption Dec;
			Dec.SetKeyWithIV(randomKey, sizeof(randomKey), randomIv);
			CryptoPP::ArraySource(ciphertext.GetData().data(), ciphertext.GetData().size(), true,
				new CryptoPP::StreamTransformationFilter(Dec, new CryptoPP::Redirector(ds)));
		}
		dec_plaintext.GetData().resize(ds.TotalPutLength());
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
	AES object;
	int mode = object.Encryption();
	object.Decryption(mode);
	system("pause");
}