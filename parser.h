#ifndef __PARSER_H__
#define __PARSER_H__

#include <string_view>

namespace http {
	struct method {
		std::string_view view;
	};

	struct protocol {
		std::string_view view;
	};

	struct header_key {
		std::string_view view;
	};

	struct header_sep {
	};

	struct header_val {
		std::string_view view;
	};

	struct dynamic_url_string {
		std::string_view view;
	};
}

class parser {
public:
	struct whitespace {
	};

	struct term {
	};

	struct ascii_word {
		std::string_view view;
	};

	struct rest {
		std::string_view view;
	};

public:
	parser() = delete;

	parser(const char *startstring) : s{ startstring }
	{
	}

	bool impl(term)
	{
		return *s == '\0';
	}

	bool impl(http::dynamic_url_string *p)
	{
		size_t i = 0;

		while (s[i] >= 0x21 && s[i] <= 0x7E && s[i] != '/' && s[i] != '?' && s[i] != '&' && s[i] != '=')
			i++;

		if (!i)
			return false;

		p->view = std::string_view{ s, i };
		s += i;
		return true;
	}

	bool impl(size_t *p)
	{
		size_t ret = 0;
		size_t i = 0;

		while (s[i] >= '0' && s[i] <= '9') {
			ret *= 10;
			ret += s[i] - '0';
			i++;
		}

		if (!i)
			return false;

		*p = ret;
		s += i;
		return true;
	}

	bool impl(http::header_sep)
	{
		size_t i = 0;

		if (s[i++] != ':')
			return false;

		while (s[i] == ' ')
			i++;

		s += i;
		return true;
	}

	bool impl(whitespace)
	{
		size_t i = 0;

		while (s[i] == ' ' || s[i] == '\t')
			i++;

		if (!i)
			return false;

		s += i;
		return true;
	}

	bool impl(ascii_word *p)
	{
		size_t i = 0;

		while (s[i] >= 0x21 && s[i] <= 0x7E)
			i++;

		if (!i)
			return false;

		p->view = std::string_view{ s, i };
		s += i;
		return true;
	}

	bool impl(http::method *p)
	{
		if (impl("GET")) {
			p->view = "GET";
			return true;
		}

		if (impl("POST")) {
			p->view = "POST";
			return true;
		}

		lasterror = "HTTP method is not supported";
		return false;
	}

	bool impl(http::protocol *p)
	{
		if (impl("HTTP/1.1")) {
			p->view = "HTTP/1.1";
			return true;
		}

		lasterror = "HTTP protocol unknown";
		return false;
	}

	bool impl(http::header_key *p)
	{
		size_t i = 0;

		while ((s[i] >= 'a' && s[i] <= 'z')
			|| (s[i] >= 'A' && s[i] <= 'Z')
			|| (s[i] >= '0' && s[i] <= '9')
			|| (s[i] == '-'))
			i++;

		if (!i)
			return false;

		p->view = std::string_view{ s, i };
		s += i;
		return true;
	}

	bool impl(http::header_val *p)
	{
		size_t i = 0;

		while (s[i] >= 0x20 && s[i] <= 0x7E)
			i++;

		if (!i)
			return false;

		p->view = std::string_view{ s, i };
		s += i;
		return true;
	}

	template <size_t N>
	bool impl(const char(&arr)[N])
	{
		for (size_t i = 0; i != N - 1; i++)
			if (s[i] != arr[i])
				return false;
		s += N - 1;
		return true;
	}

	template <typename ...Args>
	bool operator()(Args &&...args)
	{
		return (... && impl(std::forward<Args>(args)));
	}

public:
	const char *s;
	const char *lasterror = nullptr;
};

#endif
