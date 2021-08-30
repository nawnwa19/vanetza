#ifndef GENERIC_KEY_HPP_IOXLJFVZ
#define GENERIC_KEY_HPP_IOXLJFVZ

#include <string>
#include <cassert>
#include <boost/variant/variant.hpp>

#include <liboqs-cpp/include/oqs_cpp.h>
#include <vanetza/security/ecdsa256.hpp>
#include <vanetza/security/public_key.hpp>

namespace vanetza
{
namespace security
{

// forward declaration
struct Uncompressed;

namespace generic_key
{
    struct PublicKeyOQS
    {
        oqs::bytes pub_K;
        PublicKeyAlgorithm m_type;
    };
    typedef boost::variant<PublicKeyOQS, ecdsa256::PublicKey> PublicKey;

    struct PrivateKeyOQS
    {
        oqs::bytes priv_K;
        PublicKeyAlgorithm m_type;
    };
    typedef boost::variant<PrivateKeyOQS, ecdsa256::PrivateKey> PrivateKey;

    struct KeyPairOQS
    {
        PrivateKeyOQS private_key;
        PublicKeyOQS public_key;
    };
    typedef boost::variant<KeyPairOQS, ecdsa256::KeyPair> KeyPair;

    PublicKey create_public_key(const Uncompressed&);
    void serialize(OutputArchive& ar, const KeyPairOQS& key_pair,
                   PublicKeyAlgorithm algo);
    void deserialize(InputArchive& ar, KeyPairOQS& key_pair,
                     PublicKeyAlgorithm algo);

} // namespace generic_key

generic_key::PublicKeyOQS get_genericPublicKey_from_PublicKey(const PublicKey&);


} // namespace security
} // namespace vanetza


#endif /* GENERIC_KEY_HPP_IOXLJFVZ */