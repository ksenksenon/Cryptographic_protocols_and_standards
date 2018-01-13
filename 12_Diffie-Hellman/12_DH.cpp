#include "mpir.h"
#include "mpirxx.h"
#include <sstream>
#include <vector>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <MITM_DES.h>

int main()
{
	mpz_t a;
	mpz_t b;
	mpz_t P;
	mpz_t N;
	mpz_t A;
	mpz_t B;
	mpz_t keyA;
	mpz_t keyB;
	
	mpz_init(a);
	mpz_init(b);
	mpz_init(P);
	mpz_init(N);
	mpz_init(A);
	mpz_init(B);
	mpz_init(keyA);
	mpz_init(keyB);

	gmp_randstate_t state;
	gmp_randinit_mt(state);
	gmp_randseed_ui(state, time(0));

	const int buffer_size = 1024;
	char buf[buffer_size];

	bool server = true;
	WSADATA wsaData;
	
	int result = WSAStartup(MAKEWORD(2, 2), &wsaData);

	if (result != 0) 
	{
		std::cout << "WSAStartup failed: " << result << "\n";
		return result;
	}
	struct addrinfo* addr = NULL; 
							
	struct addrinfo hints;
	ZeroMemory(&hints, sizeof(hints));

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM; 
	hints.ai_protocol = IPPROTO_TCP; 
									 
	hints.ai_flags = AI_PASSIVE;

	result = getaddrinfo("127.0.0.1", "8000", &hints, &addr);
	if (result != 0)
	{
		std::cout << "getaddrinfo failed: " << result << "\n";
		WSACleanup();
		return 1;
	}
	int listen_socket = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
	if (listen_socket == INVALID_SOCKET)
	{
		std::cout << "Error at socket: " << WSAGetLastError() << "\n";
		freeaddrinfo(addr);
		WSACleanup();
		return 1;
	}
	result = bind(listen_socket, addr->ai_addr, (int)addr->ai_addrlen);

	if (result == SOCKET_ERROR) 
	{		
		server = false;
	}
	int client;
	if (server)
	{
		std::cout << "Hello! I'm server! I'm waiting for somebody..." << std::endl;
		if (listen(listen_socket, SOMAXCONN) == SOCKET_ERROR) 
		{
			std::cout << "listen failed with error: " << WSAGetLastError() << "\n";
			closesocket(listen_socket);
			WSACleanup();
			return 1;
		}
		client = accept(listen_socket, NULL, NULL);
		if (client == INVALID_SOCKET) 
		{
			std::cout << "accept failed: " << WSAGetLastError() << "\n";
			closesocket(listen_socket);
			WSACleanup();
			return 1;
		}
		else
		{
			std::cout << "Hello, client!" << std::endl;
		}

		mpz_urandomb(a, state, 300);
		
		int serv = recv(client, buf, buffer_size, 0);
		mpz_init_set_str(P, buf, 10);
		std::cout << "P: " << P << std::endl;
		std::cout << std::endl;
	
		serv = recv(client, buf, buffer_size, 0);
		mpz_init_set_str(N, buf, 10);
		std::cout << "N: " << N << std::endl;
		std::cout << std::endl;

		serv = recv(client, buf, buffer_size, 0);
		mpz_init_set_str(B, buf, 10);
		std::cout << "B: " << B << std::endl;
		std::cout << std::endl;

		mpz_powm(A, P, a, N);
		mpz_get_str(buf, 10, A);
		serv = send(client, buf, buffer_size, 0);
		std::cout << "Send A to client: " << A << std::endl;
		std::cout << std::endl;

		mpz_powm(keyA, B, a, N);
		std::cout << "KEY: " << keyA << std::endl;
		std::cout << std::endl;

		std::vector<byte> message_vect;
		std::string message = "I'm doing cryptography all days and all nights!!!";

		std::cout << "We send the message to the client: \n" << "<"<<message<<">"<< std::endl;
		for (int i = 0; i < message.size(); i++)
		{
			message_vect.push_back(message[i]);
		}
		
		mpz_get_str(buf, 10, keyA);
		std::vector<byte> key;
		for (int i = 0; i < 8; i++)
		{
			key.push_back(buf[i]);
		}
		std::vector<byte> cipher_vect;
		cipher_vect = Encryption(message_vect, key);
		
		for (int i = 0; i < cipher_vect.size(); i++)
		{
			buf[i] = cipher_vect.at(i);
		}
		serv = send(client, buf, cipher_vect.size(), 0);
	}
	else
	{
		std::cout << "Hello! I'm client! " << std::endl;
		result = connect(listen_socket, addr->ai_addr, (int)addr->ai_addrlen); 
		if (result== SOCKET_ERROR)
		{
			std::cout << "Error connection :( " << WSAGetLastError() << "\n";
			freeaddrinfo(addr);
			closesocket(listen_socket);
			WSACleanup();
			return 1;
		}

		mpz_urandomb(b, state, 300);
		mpz_urandomb(P, state, 100);
		mpz_urandomb(N, state, 1000);

		mpz_get_str(buf, 10, P);
		int client = send(listen_socket, buf, buffer_size, 0);
		std::cout << "Send P to server: " << P << std::endl;
		std::cout << std::endl;

		mpz_get_str(buf, 10, N);
		client = send(listen_socket, buf, buffer_size, 0);
		std::cout << "Send N to server: " << N << std::endl;
		std::cout << std::endl;
		
		mpz_powm(B, P, b, N);
		mpz_get_str(buf, 10, B);
		client = send(listen_socket, buf, buffer_size, 0);
		std::cout << "Send B to server: " << B << std::endl;
		std::cout << std::endl;

		client = recv(listen_socket, buf, buffer_size, 0);
		mpz_init_set_str(A, buf, 10);
		std::cout << "A: " << A << std::endl;
		std::cout << std::endl;
	
		mpz_powm(keyB, A, b, N);
		std::cout << "KEY: " << keyB << std::endl;
		std::cout << std::endl;

		client = recv(listen_socket, buf, buffer_size, 0);
		std::string message = "";
		std::vector<byte> cipher;
		for (int i = 0; i < client; i++)
		{
			message += buf[i];
		}
		for (int i = 0; i < message.size(); i++)
		{
			cipher.push_back(message[i]);
		}
		
		mpz_get_str(buf, 10, keyB);
		std::vector<byte> key;
		for (int i = 0; i < 8; i++)
		{
			key.push_back(buf[i]);
		}
		std::vector<byte> dec_plain;
		dec_plain = Decryption(cipher,key);
		std::cout << "Decrypted message:" << std::endl;
		for (int i = 0; i < dec_plain.size(); i++)
		{
			std::cout << dec_plain.at(i);
		}
		std::cout << std::endl;
	}

	closesocket(client);
	closesocket(listen_socket);
	freeaddrinfo(addr);
	WSACleanup();
	system("pause");

}