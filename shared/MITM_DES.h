#pragma once
#include "..\third-party\src\cryptopp-CRYPTOPP_5_6_5\des.h"
#include "..\third-party\src\cryptopp-CRYPTOPP_5_6_5\modes.h"
#include "..\third-party\src\cryptopp-CRYPTOPP_5_6_5\sha.h"
#include "..\third-party\src\cryptopp-CRYPTOPP_5_6_5\osrng.h"
#include "..\third-party\src\cryptopp-CRYPTOPP_5_6_5\base64.h"
#include "..\third-party\src\cryptopp-CRYPTOPP_5_6_5\hex.h"



std::vector <byte> Encryption(std::vector <byte> &plaintext, std::vector <byte> &key)
{
	std::vector<byte> ciphertext;
	ciphertext.resize(plaintext.size() + CryptoPP::DES::BLOCKSIZE);
	CryptoPP::ArraySink cs(&ciphertext[0], ciphertext.size());

	byte keyBytes[CryptoPP::DES::DEFAULT_KEYLENGTH];
	for (int i = 0; i < sizeof(keyBytes); i++)
	{
		keyBytes[i] = key.at(i);
	}

	CryptoPP::ECB_Mode<CryptoPP::DES>::Encryption Enc(keyBytes, sizeof(keyBytes));
	CryptoPP::ArraySource(plaintext.data(), plaintext.size(), true,
		new CryptoPP::StreamTransformationFilter(Enc, new CryptoPP::Redirector(cs), CryptoPP::StreamTransformationFilter::ZEROS_PADDING));

	ciphertext.resize(cs.TotalPutLength());
	return ciphertext;
}

std::vector<byte> Decryption(std::vector<byte> &ciphertext, std::vector<byte> &key)
{
	std::vector<byte> dec_plaintext;
	dec_plaintext.resize(ciphertext.size() + CryptoPP::DES::BLOCKSIZE);
	CryptoPP::ArraySink ds(&dec_plaintext[0], dec_plaintext.size());

	byte keyBytes[CryptoPP::DES::DEFAULT_KEYLENGTH];
	for (int i = 0; i < sizeof(keyBytes); i++)
	{
		keyBytes[i] = key.at(i);
	}

	CryptoPP::ECB_Mode<CryptoPP::DES>::Decryption Dec(keyBytes, sizeof(keyBytes));
	CryptoPP::ArraySource(ciphertext.data(), ciphertext.size(), true,
		new CryptoPP::StreamTransformationFilter(Dec, new CryptoPP::Redirector(ds), CryptoPP::StreamTransformationFilter::ZEROS_PADDING));

	dec_plaintext.resize(ds.TotalPutLength());
	return dec_plaintext;
}