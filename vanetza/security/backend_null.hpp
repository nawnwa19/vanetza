#ifndef BACKEND_NULL_HPP_3E6GMTPL
#define BACKEND_NULL_HPP_3E6GMTPL

#include <vanetza/security/backend.hpp>

namespace vanetza
{
namespace security
{

/**
 * \brief A backend doing nothing
 *
 * This backend is INSECURE quite obviously!
 * It will return a faked signature and silently accept all data at verification.
 */
class BackendNull : public Backend
{
public:
    static constexpr auto backend_name = "Null";

    /// \see Backend::sign_data
    Signature sign_data(const generic_key::PrivateKey& private_key, const ByteBuffer& data_buffer) override;

    /// \see Backend::verify_data
    bool verify_data(const generic_key::PublicKey& public_key, const ByteBuffer& data, const Signature& sig) override;

    /// \see Backend::decompress_point
    boost::optional<Uncompressed> decompress_point(const EccPoint& ecc_point) override;

private:
    Signature fake_signature() const;
};

} // namespace security
} // namespace vanetza

#endif /* BACKEND_NULL_HPP_3E6GMTPL */

