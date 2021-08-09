#ifndef PUBLIC_KEY_HPP_DRZFSERF
#define PUBLIC_KEY_HPP_DRZFSERF

#include <vanetza/security/ecc_point.hpp>
#include <boost/variant/variant.hpp>
#include <vanetza/security/public_key_commons.hpp>

namespace vanetza
{
namespace security
{

/// SymmetricAlgorithm specified in TS 103 097 v1.2.1, section 4.2.3
enum class SymmetricAlgorithm : uint8_t
{
    AES128_CCM = 0
};

/// PublicKeyAlgorithm specified in TS 103 097 v1.2.1, section 4.2.2
enum class PublicKeyAlgorithm : uint8_t
{
    ECDSA_NISTP256_With_SHA256 = 0,
    ECIES_NISTP256 = 1,

    DILITHIUM2 = 2,
    UNKNOWN = 239
};

/// ecdsa_nistp256_with_sha256 specified in TS 103 097 v1.2.1, section 4.2.4
struct ecdsa_nistp256_with_sha256
{
    EccPoint public_key;
};

/// ecies_nistp256 specified in TS 103 097 v1.2.1, section 4.2.4
struct ecies_nistp256
{
    SymmetricAlgorithm supported_symm_alg;
    EccPoint public_key;
};

// dilithium2 added for PQ
struct dilithium2
{
    OqsPublicKey public_key;
};


/// Profile specified in TS 103 097 v1.2.1, section 4.2.4
using PublicKey = boost::variant<ecdsa_nistp256_with_sha256, ecies_nistp256, dilithium2>;

/**
 * \brief Determines PublicKeyAlgorithm to a given PublicKey
 * \param public_key
 * \return algorithm type
 */
PublicKeyAlgorithm get_type(const PublicKey&);

/**
 * \brief Calculates size of a PublicKey
 * \param public_key
 * \return number of octets needed to serialize the PublicKey
 */
size_t get_size(const PublicKey&);

/**
 * \brief Deserializes a PublicKey from a binary archive
 * \param ar with a serialized PublicKey at the beginning
 * \param public_key to save deserialized values in
 * \return size of the deserialized publicKey
 */
size_t deserialize(InputArchive&, PublicKey&);

/**
 * \brief Serializes a PublicKey into a binary archive
 * \param ar to serialize in
 * \param public_key to serialize
 */
void serialize(OutputArchive&, const PublicKey&);

/**
 * \brief Determines key and Ecdsa signature field size related to algorithm
 * \param public_key_algorithm
 * \return required buffer size for related fields
 * */
std::size_t field_size(PublicKeyAlgorithm);

/**
 * \brief Determines signature field size related to algorithm
 * \param public_key_algorithm
 * \return required buffer size for related fields
 * */
std::size_t field_size_signature(PublicKeyAlgorithm);
std::size_t field_size_private(PublicKeyAlgorithm);

/**
 * \brief Determines field size related to algorithm
 * \param symmetric_algorithm
 * \return required buffer size for related fields
 */
std::size_t field_size(SymmetricAlgorithm);

PublicKeyAlgorithm get_algo_from_string(const std::string&);
std::string get_string_from_algo(const PublicKeyAlgorithm &);
} // namespace security
} // namespace vanetza

#endif /* PUBLIC_KEY_HPP_DRZFSERF */
