#include <iostream>
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast.hpp>
#include <ares.h>
#include <arpa/nameser.h>
#include "dns.hpp"

namespace asio = boost::asio;
using tcp = boost::asio::ip::tcp;
namespace ssl = boost::asio::ssl;
namespace beast = boost::beast;
namespace http = beast::http;


boost::asio::awaitable<void> run() {
    // auto p = SSLNetProtocol("dot.pub");
    auto p = HTTPSNetProtocol("https://doh.pub/dns-query");
    auto resolver = BaseResolver<boost::asio::ip::udp>(p);
    auto results = co_await resolver.resolve("home.ink19.cn", "443");
    BOOST_LOG_TRIVIAL(info) << results.size();
    for (auto&& result : results) {
        std::cout << result.host_name() << std::endl;
        std::cout << result.endpoint() << std::endl;
    }

    co_return;
}

int main() {
    asio::io_context io_context;
    asio::signal_set signals(io_context, SIGINT, SIGTERM);
    signals.async_wait([&io_context](const boost::system::error_code& error, int signal_number) {
        if (!error) {
            io_context.stop();
        }
    });
    
    std::cout << "Press Ctrl+C to exit" << std::endl;
    asio::co_spawn(io_context, run, asio::detached);
    io_context.run();
    return 0;
}
