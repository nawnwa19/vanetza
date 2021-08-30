#ifndef SIGNATURE_HPP_ZWPLNDVE
#define SIGNATURE_HPP_ZWPLNDVE

#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/serialization.hpp>
#include <boost/optional/optional.hpp>
#include <boost/variant/variant.hpp>
#include <future>

#include <liboqs-cpp/include/oqs_cpp.h>

namespace vanetza
{
namespace security
{

/// EcdsaSignature specified in TS 103 097 v1.2.1, section 4.2.9
struct EcdsaSignature
{
    EccPoint R;
    ByteBuffer s;
};

class EcdsaSignatureFuture
{
public:
    EcdsaSignatureFuture(const std::shared_future<EcdsaSignature>&, std::size_t);

    const EcdsaSignature& get() const;
    std::size_t size() const;

private:
    mutable std::shared_future<EcdsaSignature> m_future;
    std::size_t m_bytes;
};


struct OqsSignature
{
    OqsSignature(PublicKeyAlgorithm type)
        : sig_type{type}{};

    OqsSignature(){};    
    PublicKeyAlgorithm sig_type;
    oqs::bytes S;
};

/// Signature specified in TS 103 097 v1.2.1, section 4.2.8
typedef boost::variant<EcdsaSignature, EcdsaSignatureFuture, OqsSignature> Signature;

/**
 * brief Determines PublicKeyAlgorithm of a given Signature
 * \param signature
 * \return PublicKeyAlgorithm
 */
PublicKeyAlgorithm get_type(const Signature&);


/**
 * \brief Calculates size of a OqsSignature
 * \param signature
 * \return number of octets needed for serialization
 */
size_t get_size(const OqsSignature&);

/**
 * \brief Calculates size of a EcdsaSignature
 * \param signature
 * \return number of octets needed for serialization
 */
size_t get_size(const EcdsaSignature&);

/**
 * \brief Calculates size of a EcdsaSignatureFuture
 * \param signature
 * \return number of octets needed for serialization
 */
size_t get_size(const EcdsaSignatureFuture&);

/**
 * \brief Calculates size of a Signature
 * \param signature
 * \return number of octets needed for serialization
 */
size_t get_size(const Signature&);

/**
 * \brief Serializes a signature into a binary archive
 * \param ar to serialize in
 * \param signature
 */
void serialize(OutputArchive&, const Signature&);
void serialize(OutputArchive&, const EcdsaSignature&);
void serialize(OutputArchive&, const EcdsaSignatureFuture&);
void serialize(OutputArchive&, const OqsSignature&);

/**
 * \brief Deserializes an EcdsaSignature from a binary archive
 *  Requires PublicKeyAlgorithm for determining the signature size
 * \param ar with a serialized EcdsaSignature at the beginning
 * \param signature to deserialize
 * \param public_key_algorithm to determine the size of the signature
 * \return size of the deserialized EcdsaSignature
 */
size_t deserialize(InputArchive&, OqsSignature&, const PublicKeyAlgorithm&);

/**
 * \brief Deserializes an EcdsaSignature from a binary archive
 *  Requires PublicKeyAlgorithm for determining the signature size
 * \param ar with a serialized EcdsaSignature at the beginning
 * \param signature to deserialize
 * \param public_key_algorithm to determine the size of the signature
 * \return size of the deserialized EcdsaSignature
 */
size_t deserialize(InputArchive&, EcdsaSignature&, const PublicKeyAlgorithm&);

/**
 * \brief Deserializes a Signature from a binary archive
 * \param ar with a serialized Signature at the beginning
 * \param signature to deserialize
 * \return size of the deserialized Signature
 */
size_t deserialize(InputArchive&, Signature&);

/**
 * \brief Extracts binary signature
 * \param signature source for binary signature
 * \return signature as binary
 */
ByteBuffer extract_signature_buffer(const Signature& sig);

/**
 * Try to extract ECDSA signature from signature variant
 * \param sig Signature variant (of some type)
 * \return ECDSA signature (optionally)
 */
boost::optional<Signature> extract_signature(const Signature& sig);

} // namespace security
} // namespace vanetza


#endif /* SIGNATURE_HPP_ZWPLNDVE */
