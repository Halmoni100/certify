#ifndef BOOST_CERTIFY_CRLSET_PARSER_HPP
#define BOOST_CERTIFY_CRLSET_PARSER_HPP

#include <system_error>
#include <boost/asio/buffer.hpp>
#include <boost/endian/arithmetic.hpp>

namespace boost
{

namespace certify
{

namespace detail
{

template<class T>
struct inline_global
{
    static T value;
};

template<class T>
T inline_global<T>::value{};

} // namespace detail

enum class crlset_error
{
    header_length_truncated,
    header_truncated,
    serial_truncated
};

class crlset_parser_category : public std::error_category
{
public:
    char const* name() const noexcept override;

    std::string message(int ev) const override;
};

std::error_code
make_error_code(crlset_error ev);

struct crlset
{
    std::array<std::uint8_t, 32> parent_spki_hash;
    std::vector<std::string> serials;
};

std::vector<crlset>
parse_crlset(asio::const_buffer b, std::error_code& ec);

std::vector<crlset>
parse_crlset(boost::asio::const_buffer b);

} // namespace certify


} // namespace boost

template<>
struct std::is_error_code_enum<::boost::certify::crlset_error> : public std::true_type{};

#include <boost/certify/impl/crlset_parser.ipp>

#endif // BOOST_CERTIFY_CRLSET_PARSER_HPP
