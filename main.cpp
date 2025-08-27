#define WIN32_LEAN_AND_MEAN

#include <WinSock2.h>

#include <iostream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <thread>
#include <fstream>

#include "parser.h"

#pragma comment(lib, "Ws2_32.lib")

struct request_container {
	http::method		request_method;
	parser::ascii_word	request_destination;
	http::protocol		request_protocol;

	std::unordered_map<std::string, std::string> headers;
};

struct response_container {
	std::string			responsebody, response;
};

static std::string create_replaced_string(
	const std::string &input,
	const std::unordered_map<std::string, std::string> &replacements)
{
	std::string result;

	size_t i = 0;
	while (i < input.size()) {
		if (input[i] == '{' && input[i + 1] == '{') {
			i += 2;
			const auto beginpos = input.c_str() + i;

			/* Since the HTML pages here are by developers we don't worry too much about malicious edge cases */
			while (input[i] != '}' && input[i + 1] != '}')
				i++;

			const auto endpos = input.c_str() + i;
			i += 3;

			std::string v{ beginpos, (size_t) (endpos - beginpos + 1) };
			
			const auto lookup = replacements.find(v);
			if (lookup != replacements.end()) {
				result.append(lookup->second);
			} else {
				result.append("{{").append(v).append("}}");
			}
		} else {
			result += input[i++];
		}
	}

	return result;
}

/*
static unsigned long long timestamp_ns()
{
	auto now = std::chrono::high_resolution_clock::now();
	auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
	return nanos;
}
*/

/* 1 means OK, 0 means no match and -1 is match but internal error */
static constexpr int (*endpoints[])(const char *, request_container &, response_container &) = {
	// GET /template
	[](const char *s, request_container &req, response_container &res) -> int {
		parser p{ s };
		if (!p("/template"))
			return 0;

		std::unordered_map<std::string, std::string> mappings;
		http::dynamic_url_string key, val;
		if (p("?")) {
			do {
				while (p(&key, "=", &val)) {
					mappings.insert({ std::string{key.view}, std::string{val.view} });
					std::cout << key.view << "=" << val.view << "\n";
				}
			} while (p("&"));
		}

		if (!p(parser::term{})) {
			res.responsebody = "The request is malformed";
			res.response.append("HTTP/1.1 400 Malformed Request\r\n");
			res.response.append("Content-Type: text/plain\r\n");
			return -1;
		}

		std::ifstream file{ "template.html" };
		std::string content{ std::istreambuf_iterator<char>{file}, std::istreambuf_iterator<char>{} };
		
		res.responsebody.append(create_replaced_string(content, mappings));

		res.response.append("HTTP/1.1 200 OK\r\n");
		res.response.append("Content-Type: text/html\r\n");

		return 1;
	},

	// GET /
	[](const char *s, request_container &req, response_container &res) -> int {
		parser p{s};
		if (!p("/", parser::term{}))
			return 0;

		std::ifstream file("index.html");
		std::string content{ std::istreambuf_iterator<char>{file}, std::istreambuf_iterator<char>{} };

		std::string headertable;
		headertable.append("<table>\n");
		headertable.append("<tr><th>Header</th><th>Value</th></tr>");
		for (const auto &[k, v] : req.headers)
			headertable.append("<tr><td>").append(k).append("</td><td>").append(v).append("</tr>\n");
		headertable.append("</table>\n");

		std::unordered_map<std::string, std::string> replacements = {
			{"headertable",		headertable},
			{"method",			std::string{ req.request_method.view }},
			{"destination",		std::string{ req.request_destination.view }},
			{"protocol",		std::string{ req.request_protocol.view}}
		};
		res.responsebody.append(create_replaced_string(content, replacements));

		res.response.append("HTTP/1.1 200 OK\r\n");
		res.response.append("Content-Type: text/html\r\n");
		return 1;
	},

	// This is the 404 Not Found handler
	[](const char *s, request_container &req, response_container &res) -> int {
		res.responsebody.append("The requested endpoint '").append(s).append("' could not be found.");

		res.response.append("HTTP/1.1 404 Not Found\r\n");
		res.response.append("Content-Type: text/plain\r\n");
		return 1;
	}
};

static bool handle_request(SOCKET clientfd)
{
	char recv_buf[2048] = {};
	int rx = 0;

	for (;;) {
		const auto recv_result = recv(clientfd, recv_buf + rx, sizeof(recv_buf) - rx, 0);
		if (recv_result == 0) {
			std::cout << "Client disconnected\n";
			return false;
		}

		if (recv_result == SOCKET_ERROR) {
			std::cerr << "recv failed with error " << WSAGetLastError() << "\n";
			return false;
		}

		rx += recv_result;
		if (rx == sizeof(recv_buf)) {
			std::cerr << "Buffer limit reached\n";
			return false;
		}

		/* At this point data has been received, but it's not known if it can be parsed
		 * The HTTP protocol ends after \r\n\r\n, so we can check for that
		 */
		if (rx < 4)
			continue;

		bool request_is_parsable = false;
		for (int i = 0; i <= (rx - 4); i++) {
			if (recv_buf[i] == '\r'
				&& recv_buf[i + 1] == '\n'
				&& recv_buf[i + 2] == '\r'
				&& recv_buf[i + 3] == '\n')
			{
				request_is_parsable = true;
				break;
			}
		}

		if (!request_is_parsable)
			continue;

		request_container	req;
		parser				p{ recv_buf };

		auto get_remaining_chars_of_current_parser_line = [&]() {
			const size_t chars_remaining_in_buffer = rx - (p.s - recv_buf);
			size_t chars_remaining_in_line = 0;
			for (size_t i = 0; i < chars_remaining_in_buffer; i++) {
				if (p.s[i] < 0x20 || p.s[i] > 0x7E)
					break;

				chars_remaining_in_line++;
			}

			return std::string_view{ p.s, chars_remaining_in_line };
		};

		if (!p(&req.request_method,
			parser::whitespace{},
			&req.request_destination,
			parser::whitespace{},
			&req.request_protocol,
			"\r\n"))
		{
			std::cerr << "Parser error -- " << p.lasterror << " at: " << get_remaining_chars_of_current_parser_line() << "...\n";
			return false;
		}

		http::header_key key;
		http::header_val val;
		while (p(&key, http::header_sep{}, &val, "\r\n")) {
			auto lookup = req.headers.find(std::string{ key.view });
			if (lookup != req.headers.end()) {
				lookup->second.append(", ").append(val.view);
				continue;
			}

			req.headers.insert({ std::string{ key.view }, std::string{ val.view } });
		}

		if (!p("\r\n")) {
			std::cerr << "Expected end of headers\n";
			return false;
		}

		if ((p.s - recv_buf) != rx) {
			std::cerr << "Payloads are not supported yet\n";
			std::cerr << get_remaining_chars_of_current_parser_line() << "\n";
			return false;
		}

		std::string dest_as_string{ req.request_destination.view };
		response_container res;
		for (auto ep : endpoints) {
			const auto matchresult = ep(dest_as_string.c_str(), req, res);
			if (matchresult != 0)
				break;
		}

		bool should_keep_alive = true;
		const auto lookup_header_connection = req.headers.find("Connection");
		if (lookup_header_connection != req.headers.end() && lookup_header_connection->second == "close") {
			should_keep_alive = false;
			res.response.append("Connection: close\r\n");
		}
		res.response.append("Content-Length: ").append(std::to_string(res.responsebody.size())).append("\r\n");
		res.response.append("\r\n");
		res.response.append(res.responsebody);

		int tx = 0;
		for (;;) {
			const auto send_result = send(clientfd, res.response.c_str()+tx, (int) res.response.size()-tx, 0);
			if (send_result == SOCKET_ERROR) {
				std::cerr << "Accept failed with error " << WSAGetLastError() << "\n";
				return false;
			}

			tx += send_result;
			if (send_result == res.response.size()) {
				std::cout << "Entire response successfully sent\n";
				return should_keep_alive;
			}
		}
	}
}

static int _main()
{
	// https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsastartup#:~:text=The%20current%20version%20of%20the%20Windows%20Sockets%20specification%20is%20version%202.2
	WSADATA wsaData = {};
	const auto initWinSockResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (initWinSockResult) {
		std::cerr << "WinSock initialization failed with error code: " << initWinSockResult << "\n";
		return EXIT_FAILURE;
	}

	const auto atexit_result = atexit([]() {
		const auto wsa_cleanup_result = WSACleanup();
		if (wsa_cleanup_result)
			std::cerr << "WSACleanup returned " << wsa_cleanup_result << "\n";
	});

	if (atexit_result) {
		std::cerr << "Could not register shutdown function\n";
		return EXIT_FAILURE;
	}

	const auto listenfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listenfd == -1) {
		std::cerr << "Could not create listening socket, error = " << WSAGetLastError() << "\n";
		return EXIT_FAILURE;
	}

	sockaddr_in bindaddr = {};
	bindaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	bindaddr.sin_family = AF_INET;
	bindaddr.sin_port = htons(3000);
	const auto bindResult = bind(listenfd, (sockaddr *) &bindaddr, sizeof(bindaddr));
	if (bindResult) {
		std::cerr << "Could not bind listening socket, error " << WSAGetLastError() << "\n";
		return EXIT_FAILURE;
	}

	const char one = 1;
	const auto setsockoptResult = setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (setsockoptResult) {
		std::cerr << "Could not set socket option REUSEADDR, error = " << WSAGetLastError() << "\n";
		return EXIT_FAILURE;
	}

	const auto listen_result = listen(listenfd, 128);
	if (listen_result) {
		std::cerr << "Could not listen on socket, error = " << WSAGetLastError() << "\n";
		return EXIT_FAILURE;
	}

	std::printf("Accepting connections on port %d\n", ntohs(bindaddr.sin_port));

	for (;;) {
		const auto acceptResult = accept(listenfd, nullptr, nullptr);
		if (acceptResult == SOCKET_ERROR) {
			std::cerr << "Accept failed with error " << WSAGetLastError() << "\n";
			continue;
		}
		const auto clientfd = acceptResult;

		std::thread{ [clientfd]() {
			int numserved = 0;
			while (handle_request(clientfd))
				std::printf("Served %d requests on same connection\n", ++numserved);

			if (closesocket(clientfd) == SOCKET_ERROR) {
				std::cerr << "Failed to close socket with error " << WSAGetLastError() << "\n";
			}
		}}.detach();
	}

	return EXIT_SUCCESS;
}

int main()
{
	_main();
}

