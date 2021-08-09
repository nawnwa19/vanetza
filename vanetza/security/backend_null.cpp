#include <vanetza/common/byte_sequence.hpp>
#include <vanetza/security/backend_null.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/signature.hpp>

namespace vanetza
{
namespace security
{

Signature BackendNull::sign_data(const generic_key::PrivateKey&, const ByteBuffer&)
{
    static const Signature fake = fake_signature();
    return fake;
}

bool BackendNull::verify_data(const generic_key::PublicKey&, const ByteBuffer&, const Signature&)
{
    // accept everything
    return true;
}

boost::optional<Uncompressed> BackendNull::decompress_point(const EccPoint& ecc_point)
{
    return boost::none;
}

Signature BackendNull::fake_signature() const
{
    const std::size_t size = field_size(PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256);
    EcdsaSignature signature;
    X_Coordinate_Only coordinate;
    coordinate.x = random_byte_sequence(size, 0xdead);
    signature.R = coordinate;
    signature.s = random_byte_sequence(size, 0xbeef);

    return Signature{ signature };
}

} // namespace security
} // namespace vanetza
