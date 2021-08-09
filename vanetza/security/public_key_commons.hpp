#ifndef PUBLIC_KEY_COMMONS_HPP_XCESTUEB
#define PUBLIC_KEY_COMMONS_HPP_XCESTUEB

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/serialization.hpp>
#include <boost/variant/variant.hpp>
#include <cstdint>
#include <liboqs-cpp/include/oqs_cpp.h>

namespace vanetza
{
namespace security
{

/// forward declaration, see public_key.hpp
enum class PublicKeyAlgorithm: uint8_t;

/// Defining a generic public key type for oqs
// using OqsPublicKey = oqs::bytes;
struct OqsPublicKey
{
   oqs::bytes K;
};

/**
 * \brief Serializes an OqsPublicKey into a binary archive
 * \param ar to serialize in
 * \param public_key to serialize
 * \param pka Public key algorithm used
 */
void serialize(OutputArchive&, const OqsPublicKey&, PublicKeyAlgorithm);

/**
 * \brief Deserializes an OqsPublicKey from a binary archive
 * \param ar with a serialized OqsPublicKey at the beginning,
 * \param public_key to deserialize
 * \param pka to get field size of the algorithm
 */
void deserialize(InputArchive&, OqsPublicKey&, PublicKeyAlgorithm);

/**
 * \brief Calculates size of an OqsPublicKey
 * \param public_key
 * \return size_t containing the number of octets needed to serialize the OqsPublicKey
 */
size_t get_size(const OqsPublicKey&);

} //namespace security
} //namespace vanetza

#endif /* ECC_POINT_HPP_XCESTUEB */
