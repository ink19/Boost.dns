#ifndef BOOST_DNS_HPP
#define BOOST_DNS_HPP

#include <ares.h>
#include <arpa/nameser.h>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/url.hpp>
#include <fmt/format.h>
#include <string>

namespace asio = boost::asio;
using tcp = boost::asio::ip::tcp;
namespace ssl = boost::asio::ssl;
namespace beast = boost::beast;
namespace http = beast::http;

static const std::string base64_encode(const std::string &s) {
    std::string res;
    res.assign(beast::detail::base64::encoded_size(s.size()), ' ');
    beast::detail::base64::encode(res.data(), s.data(),
                                  s.size());
    return res;
}

class NetProtocol {
public:
  virtual boost::asio::awaitable<const std::string>
  request(const std::string &req) = 0;
};

class HTTPSNetProtocol : public NetProtocol {
public:
  HTTPSNetProtocol(std::string uri) {
    const auto puri = boost::urls::parse_uri_reference(uri).value();
    m_host = puri.host();
    m_port = puri.port();
    if (m_port == "") {
      m_port = "443";
    }
    m_path = puri.path();
  }

  virtual boost::asio::awaitable<const std::string>
  request(const std::string &req) override {
    const auto context = co_await asio::this_coro::executor;
    tcp::resolver resolver(context);
    auto endpoints =
        co_await resolver.async_resolve(m_host, m_port, asio::use_awaitable);
    ssl::context ctx(ssl::context::tls_client);
    ctx.set_default_verify_paths();

    ssl::stream<tcp::socket> stream(context, ctx);
    co_await stream.lowest_layer().async_connect(endpoints->endpoint(),
                                                 asio::use_awaitable);

    if (!SSL_set_tlsext_host_name(stream.native_handle(), m_host.c_str())) {
      boost::system::error_code ec{static_cast<int>(::ERR_get_error()),
                                   boost::asio::error::get_ssl_category()};
      co_return "";
    }
    co_await stream.async_handshake(ssl::stream_base::client,
                                    asio::use_awaitable);

    std::string encode_dns_req = base64_encode(req);

    http::request<http::string_body> http_req{
        http::verb::get, m_path + "?dns=" + encode_dns_req, 11};
    http_req.set(http::field::host, m_host);
    http_req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
    http_req.set(http::field::accept, "application/dns-message");
    http_req.keep_alive(false);
    co_await http::async_write(stream, http_req, asio::use_awaitable);

    beast::flat_buffer b;
    http::response<http::dynamic_body> res;
    co_await http::async_read(stream, b, res, asio::use_awaitable);
    std::string response_body = beast::buffers_to_string(res.body().data());

    co_return response_body;
  }

private:
  std::string m_host;
  std::string m_port;
  std::string m_path;
};

class SSLNetProtocol : public NetProtocol {
public:
  SSLNetProtocol(std::string host, std::string port = "853") {
    m_host = host;
    m_port = port;
  }

  virtual boost::asio::awaitable<const std::string>
  request(const std::string &req) override {
    const auto context = co_await asio::this_coro::executor;
    tcp::resolver resolver(context);
    auto endpoints =
        co_await resolver.async_resolve(m_host, m_port, asio::use_awaitable);
    ssl::context ctx(ssl::context::tls_client);
    ctx.set_default_verify_paths();

    ssl::stream<tcp::socket> stream(context, ctx);
    co_await stream.lowest_layer().async_connect(endpoints->endpoint(),
                                                 asio::use_awaitable);
    BOOST_LOG_TRIVIAL(info) << "SSL handshake";
    if (!SSL_set_tlsext_host_name(stream.native_handle(), m_host.c_str())) {
      boost::system::error_code ec{static_cast<int>(::ERR_get_error()),
                                   boost::asio::error::get_ssl_category()};
      BOOST_LOG_TRIVIAL(error) << ec.message();
      co_return "";
    }
    co_await stream.async_handshake(ssl::stream_base::client,
                                    asio::use_awaitable);

    boost::asio::const_buffer req_buff(req.data(), req.size());
    co_await stream.async_write_some(req_buff, asio::use_awaitable);

    char buff[1024];
    boost::asio::mutable_buffer response(buff, 1024);

    co_await stream.async_read_some(response, asio::use_awaitable);
    // co_await stream.async_shutdown(asio::use_awaitable);
    stream.lowest_layer().close();

    auto rsp =  std::string((unsigned char *)response.data(),
                          (unsigned char *)response.data() + response.size());

    BOOST_LOG_TRIVIAL(info) << base64_encode(rsp);

    co_return rsp;
  }

private:
  std::string m_host;
  std::string m_port;
};


template<typename ProtocolType>
class BaseResolver {
public:
  BaseResolver(NetProtocol &protocol) : m_protocol(protocol) {}
  virtual boost::asio::awaitable<boost::asio::ip::basic_resolver_results<tcp>>
  resolve(const std::string &host, const std::string &port) {
    unsigned char *buff;
    int len;
    ares_create_query(host.c_str(), ns_c_in, ns_t_a, 1024, 3, &buff, &len, 512);
    const auto rsp =
        co_await m_protocol.request(std::string(buff, buff + len));

    struct hostent *hosts;
    int ret = ares_parse_a_reply((const unsigned char *)rsp.data(), rsp.size(),
                                 &hosts, NULL, NULL);
    if (ret != ARES_SUCCESS) {
      BOOST_LOG_TRIVIAL(error)
          << fmt::format("ares_parse_a_reply failed. code: {}, message: {}",
                         ret, ares_strerror(ret));
      co_return boost::asio::ip::basic_resolver_results<tcp>();
    }

    std::vector<boost::asio::ip::tcp::endpoint> results;
    for (int i = 0; hosts->h_addr_list[i] != NULL; ++i) {
      boost::asio::ip::basic_endpoint<ProtocolType> ep(
          boost::asio::ip::make_address_v4(
              ntohl(*(uint32_t *)hosts->h_addr_list[i])),
          std::stoi(port));
      results.push_back(ep);
    }
    ares_free_hostent(hosts);

    auto presult = boost::asio::ip::basic_resolver_results<ProtocolType>::create(
        results.begin(), results.end(), host, port);

    co_return presult;
  };

private:
  NetProtocol &m_protocol;
};

#endif
