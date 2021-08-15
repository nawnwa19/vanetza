#include <vanetza/security/generic_key.hpp>
#include <vanetza/security/public_key.hpp>
#include <boost/variant.hpp>
#include <cassert>
namespace vanetza
{
namespace security
{

namespace generic_key
{
PublicKey create_public_key(const Uncompressed &)
{
    ecdsa256::PublicKey pb;
    //     assert(unc.x.size() == pb.x.size());
    //     assert(unc.y.size() == pb.y.size());
    //     std::copy_n(unc.x.begin(), pb.x.size(), pb.x.begin());
    //     std::copy_n(unc.y.begin(), pb.y.size(), pb.y.begin());
    return pb;
}

void serialize(OutputArchive& ar, const KeyPairOQS& key_pair,
               PublicKeyAlgorithm algo) {
    const auto& private_key = key_pair.private_key;
    const auto& public_key = key_pair.public_key;

    assert(private_key.priv_K.size() == field_size_private(algo));
    assert(public_key.pub_K.size() == field_size(algo));

    assert(private_key.m_type == public_key.m_type);

    // Serialize the private key first
    // Serialize name and then the private key
    serialize(ar, private_key.m_type);
    for (auto& byte : private_key.priv_K) ar << byte;

    // Serialize the public key
    for (auto& byte : public_key.pub_K) ar << byte;
}

void deserialize(InputArchive& ar, KeyPairOQS& key_pair,
                 PublicKeyAlgorithm algo) {
    auto& private_key = key_pair.private_key;
    auto& public_key = key_pair.public_key;

    // Deserialize the type and assert if no match
    PublicKeyAlgorithm pka_recovered = PublicKeyAlgorithm::UNKNOWN;
    deserialize(ar, pka_recovered);
    assert(pka_recovered == algo);
    private_key.m_type = pka_recovered;
    public_key.m_type = pka_recovered;

    // Resize the key buffers
    size_t size_priv = field_size_private(algo);
    size_t size_pub = field_size(algo);
    private_key.priv_K.resize(size_priv);
    public_key.pub_K.resize(size_pub);

    // Deserialize the private key first
    size_t c;
    for ( c = 0; c < size_priv; c++) ar >> private_key.priv_K[c];
    size_t d;
    // Deserialize the public key
    for (d = 0; d < size_pub; d++) ar >> public_key.pub_K[d];
}

}  // namespace generic_key

generic_key::PublicKeyOQS get_genericPublicKey_from_PublicKey(
    const PublicKey& pub_key) {
    generic_key::PublicKeyOQS oqs_key;
    auto visitor = generic_key::compose(
        // For ECDSA256
        [&](const ecdsa_nistp256_with_sha256& pub_key) { return oqs_key; },
        // For ECIES future
        [&](const ecies_nistp256& pub_key) { return oqs_key; },

        // For OQS types
        [&](const oqs_nist& pub_key) {
            oqs_key.pub_K = pub_key.public_key.K;
            oqs_key.m_type = pub_key.type;
            return oqs_key;
        });

    return boost::apply_visitor(visitor, pub_key);
}

} // namespace security
} // namespace vanetza
