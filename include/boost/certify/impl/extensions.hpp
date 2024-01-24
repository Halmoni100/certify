#ifndef BOOST_CERTIFY_IMPL_EXTENSIONS_HPP
#define BOOST_CERTIFY_IMPL_EXTENSIONS_HPP

#include <boost/certify/extensions.hpp>

namespace boost
{
namespace certify
{

template<class AsyncStream>
string_view
sni_hostname(asio::ssl::stream<AsyncStream> const& stream)
{
    auto handle =
      const_cast<asio::ssl::stream<AsyncStream>&>(stream).native_handle();
    auto* hostname = SSL_get_servername(handle, TLSEXT_NAMETYPE_host_name);
    if (hostname == nullptr)
        return string_view{};
    return {hostname};
}

template<class AsyncStream>
string_view
sni_hostname(beast::ssl_stream<AsyncStream> const& stream)
{
    auto handle =
      const_cast<asio::ssl::stream<AsyncStream>&>(stream).native_handle();
    auto* hostname = SSL_get_servername(handle, TLSEXT_NAMETYPE_host_name);
    if (hostname == nullptr)
        return string_view{};
    return {hostname};
}

template<class AsyncStream>
void
sni_hostname(asio::ssl::stream<AsyncStream>& stream,
             std::string const& hostname,
             std::error_code& ec)
{
    auto ret =
      SSL_set_tlsext_host_name(stream.native_handle(), hostname.c_str());
    if (ret == 0)
        ec = {static_cast<int>(::ERR_get_error()),
              asio::error::get_ssl_category()};
    else
        ec = {};
}

template<class AsyncStream>
void
sni_hostname(asio::ssl::stream<AsyncStream>& stream,
             std::string const& hostname)
{
    std::error_code ec;
    sni_hostname(stream, hostname, ec);
    if (ec)
        throw std::system_error{ec};
}

template<class AsyncStream>
void
sni_hostname(beast::ssl_stream<AsyncStream>& stream,
             std::string const& hostname)
{
    auto ret =
      SSL_set_tlsext_host_name(stream.native_handle(), hostname.c_str());
    if (ret == 0) {
        std::error_code ec = {static_cast<int>(::ERR_get_error()),
              asio::error::get_ssl_category()};
        throw ec;
    }
}

} // namespace certify
} // namespace boost

#endif // BOOST_CERTIFY_IMPL_EXTENSIONS_HPP
