#include <time.h>
#include "MyFile.h"
#include "MITM_DES.h"

std::vector <byte> fKey(int keySize)
{
	srand(time(NULL));
	std::vector <byte> firstKey;
	for (int i = 0; i < keySize; i++)
	{
		firstKey.push_back(rand() % 256);
	}
	return firstKey;
}

std::vector <byte> KeyGener(std::vector <byte> &prevKey, int keySize)
{
	std::vector <byte> nextKey;
	nextKey.resize(prevKey.size());
	int j = 15;
	for (int i = 0; i < keySize; i++)
	{
		nextKey[i] = prevKey[i];
	}
	nextKey[j] = nextKey[j] + 1;
	if (nextKey[j] == 0)
	{
		while (nextKey[j] == 0)
		{
			j--;
			nextKey[j] = nextKey[j] + 1;
		}
	}
	return nextKey;
}

void partition(std::vector<std::vector<byte>> &keysArray, std::vector <byte> &left, std::vector <byte> &right, int num)
{
	for (int i = 0; i < 8; i++)
	{
		left.push_back(keysArray[num].at(i));
	}
	for (int i = 8; i < 16; i++)
	{
		right.push_back(keysArray[num].at(i));
	}
}

void createPair(std::map<std::vector<byte>, std::vector<byte>> &e, std::map<std::vector<byte>, std::vector<byte>> &d,
	std::vector<std::vector<byte>> &keysArray, std::vector <byte> &plain, std::vector <byte> &cipher, int start, int stop)
{
	std::vector <byte> left;
	std::vector <byte> right;
	for (int i = start; i < stop; i++)
	{
		left.clear();
		right.clear();
		partition(keysArray, left, right, i);
		e.insert(std::pair<std::vector<byte>, std::vector<byte>>(left, Encryption(plain, left)));
		d.insert(std::pair<std::vector<byte>, std::vector<byte>>(right, Decryption(cipher, right)));
	}
}

int main()
{
	int start;
	int stop;

	int keySize = 16;
	std::cout << "Please wait..." << std::endl;
	srand(time(NULL));
	std::string plaintext = "Love love love <3";
	std::vector <byte> plain_vect;

	for (int i = 0; i < plaintext.size(); i++)
	{
		plain_vect.push_back(plaintext[i]);
	}

	std::vector <byte> cipher_vect;
	std::vector <byte> firstKey;
	firstKey = fKey(keySize);

	int count = 65536;
	std::vector<std::vector<byte>> keysArray;

	std::vector <byte> newKey;
	newKey = firstKey;

	for (int i = 0; i < count; i++)
	{
		keysArray.push_back(newKey);
		newKey = KeyGener(newKey, keySize);
	}

	int keyNum = rand() % count;
	std::vector <byte> left;
	std::vector <byte> right;
	partition(keysArray, left, right, keyNum);

	cipher_vect = Encryption(Encryption(plain_vect, left), right);

	std::map<std::vector<byte>, std::vector<byte>> e;
	std::map<std::vector<byte>, std::vector<byte>> d;

	start = clock();
	std::thread Thread1(createPair, std::ref(e), std::ref(d), keysArray, plain_vect, cipher_vect, 0, 8192);
	std::thread Thread2(createPair, std::ref(e), std::ref(d), keysArray, plain_vect, cipher_vect, 8192, 16384);
	std::thread Thread3(createPair, std::ref(e), std::ref(d), keysArray, plain_vect, cipher_vect, 16384, 24576);
	std::thread Thread4(createPair, std::ref(e), std::ref(d), keysArray, plain_vect, cipher_vect, 24576, 32768);
	std::thread Thread5(createPair, std::ref(e), std::ref(d), keysArray, plain_vect, cipher_vect, 32768, 40960);
	std::thread Thread6(createPair, std::ref(e), std::ref(d), keysArray, plain_vect, cipher_vect, 40960, 49152);
	std::thread Thread7(createPair, std::ref(e), std::ref(d), keysArray, plain_vect, cipher_vect, 49152, 57344);
	std::thread Thread8(createPair, std::ref(e), std::ref(d), keysArray, plain_vect, cipher_vect, 57344, 65536);
	
	system("cls");
	std::cout << "Building a table in the process" << std::endl;
	Thread1.join();
	Thread2.join();
	Thread3.join();
	Thread4.join();
	Thread5.join();
	Thread6.join();
	Thread7.join();
	Thread8.join();

	stop = clock();
	system("cls");
	std::cout << "Build time: " << (stop - start) / 1000.0 << " seconds" << std::endl;
	std::vector<byte> findLeft;
	std::vector<byte> findRight;

	bool search = false;
	for (auto item_e : e)
	{
		for (auto item_d : d)
		{
			if (item_e.second == item_d.second)
			{
				search = true;
				findLeft = item_e.first;
				findRight = item_d.first;
				break;
			}
		}
	}

	plain_vect = Decryption(Decryption(cipher_vect, findRight), findLeft);

	if (!search)
	{
		std::cout << "Key is not found" << std::endl;
	}
	else
	{
		std::cout << "The decryption result with the key found: \n";
		for (int i = 0; i < plain_vect.size(); i++)
		{
			std::cout << plain_vect.at(i);
		}
		std::cout << std::endl;
	}

	Thread1.~thread();
	Thread2.~thread();
	Thread3.~thread();
	Thread4.~thread();
	Thread5.~thread();
	Thread6.~thread();
	Thread7.~thread();
	Thread8.~thread();
	system("pause");
	return 0;
}

