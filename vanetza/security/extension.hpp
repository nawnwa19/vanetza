#ifndef EXTENSION_HPP_LWBWIAVL
#define EXTENSION_HPP_LWBWIAVL

#include <vanetza/security/signature.hpp>
#include <vanetza/security/public_key_commons.hpp> 
#include <boost/optional/optional.hpp>

namespace vanetza
{
namespace security
{
struct Extension
{
    OqsPublicKey hybrid_key;
    OqsSignature hybrid_sig;
};

size_t get_size(const Extension& ext);

void serialize(OutputArchive& ar, const Extension& ext);

size_t deserialize(InputArchive& ar, Extension& ext);

boost::optional<Extension> extract_extension(const Extension& ext);

} // namespace security
} // namespace vanetza

#endif