#include <vanetza/security/exception.hpp>
#include <vanetza/security/signature.hpp>
#include <vanetza/security/variant_lambda_helper.hpp>
#include <boost/iostreams/stream.hpp>
#include <cassert>

namespace vanetza
{
namespace security
{

PublicKeyAlgorithm get_type(const Signature& sig)
{
    struct Signature_visitor : public boost::static_visitor<PublicKeyAlgorithm>
    {
        PublicKeyAlgorithm operator()(const EcdsaSignature& sig)
        {
            return PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256;
        }

        PublicKeyAlgorithm operator()(const EcdsaSignatureFuture& sig)
        {
            return PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256;
        }

        PublicKeyAlgorithm operator()(const OqsSignature& sig)
        {
            return sig.sig_type;
        }
    };
    Signature_visitor visit;
    return boost::apply_visitor(visit, sig);
}

size_t get_size(const EcdsaSignature& sig)
{
    size_t size = sig.s.size();
    size += get_size(sig.R);
    return size;
}

size_t get_size(const EcdsaSignatureFuture& sig)
{
    return sig.size();
}

size_t get_size(const OqsSignature& sig)
{
    return sig.S.size();
}

size_t get_size(const Signature& sig)
{
    size_t size = sizeof(PublicKeyAlgorithm);
    struct Signature_visitor : public boost::static_visitor<size_t>
    {
        size_t operator()(const EcdsaSignature& sig)
        {
            return get_size(sig);
        }

        size_t operator()(const EcdsaSignatureFuture& sig)
        {
            return get_size(sig);
        }

        size_t operator()(const OqsSignature& sig)
        {
            return get_size(sig);
        }
    };
    Signature_visitor visit;
    size += boost::apply_visitor(visit, sig);
    return size;
}

void serialize(OutputArchive& ar, const Signature& sig)
{
    struct signature_visitor : public boost::static_visitor<>
    {
        signature_visitor(OutputArchive& ar) : m_archive(ar) {}

        void operator()(const EcdsaSignature& sig)
        {
            serialize(m_archive, sig);
        }

        void operator()(const EcdsaSignatureFuture& sig)
        {
            serialize(m_archive, sig);
        }

        void operator()(const OqsSignature& sig)
        {
            serialize(m_archive, sig);
        }

        OutputArchive& m_archive;
    };

    PublicKeyAlgorithm algo = get_type(sig);
    serialize(ar, algo);
    signature_visitor visitor(ar);
    boost::apply_visitor(visitor, sig);
}

void serialize(OutputArchive& ar, const EcdsaSignature& sig)
{
    const PublicKeyAlgorithm algo = PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256;
    assert(field_size(algo) == sig.s.size());

    serialize(ar, sig.R, algo);
    for (auto& byte : sig.s) {
        ar << byte;
    }
}

void serialize(OutputArchive& ar, const EcdsaSignatureFuture& sig)
{
    auto& ecdsa = sig.get();
    serialize(ar, ecdsa);
}

void serialize(OutputArchive& ar, const OqsSignature& sig)
{
    const PublicKeyAlgorithm algo = sig.sig_type;
    assert(field_size_signature(algo) == sig.S.size());
    
    for (auto& byte : sig.S){
        ar << byte;
    }
}

size_t deserialize(InputArchive& ar, EcdsaSignature& sig, const PublicKeyAlgorithm& algo)
{
    EccPoint point;
    ByteBuffer buf;
    deserialize(ar, point, algo);
    for (size_t i = 0; i < field_size(algo); i++) {
        uint8_t byte;
        ar >> byte;
        buf.push_back(byte);
    }
    sig.R = point;
    sig.s = buf;
    return get_size(sig);
}

size_t deserialize(InputArchive &ar, OqsSignature &sig, const PublicKeyAlgorithm &algo)
{
    sig.sig_type = algo;
    size_t size = field_size_signature(algo);

    uint8_t elem;
    for (size_t c = 0; c < size; c++) {
        ar >> elem;
        sig.S.push_back(elem);
    }
    
    return get_size(sig);
}

size_t deserialize(InputArchive& ar, Signature& sig)
{
    PublicKeyAlgorithm algo;
    size_t size = 0;
    deserialize(ar, algo);
    size += sizeof(algo);
    switch (algo) {
        case PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256: {
            EcdsaSignature signature;
            size += deserialize(ar, signature, algo);
            sig = signature;
            break;
        }
        case PublicKeyAlgorithm::ECIES_NISTP256:
        case PublicKeyAlgorithm::UNKNOWN:
            assert(false && "Unknown PublicKeyAlgorithm");
        default: {
            OqsSignature signature(algo);
            size += deserialize(ar, signature, algo);
            sig = signature;
            break;
        }
    }
    return size;
}

ByteBuffer extract_signature_buffer(const Signature& sig)
{
    struct extraction_visitor : public boost::static_visitor<>
    {
        void operator()(const EcdsaSignature& sig)
        {
            m_buffer = convert_for_signing(sig.R);
            m_buffer.insert(m_buffer.end(), sig.s.begin(), sig.s.end());
        }

        void operator()(const EcdsaSignatureFuture& sig_future)
        {
            const EcdsaSignature& sig = sig_future.get();
            (*this)(sig);
        }

        void operator()(const OqsSignature& sig)
        {
            m_buffer = sig.S;
        }

        ByteBuffer m_buffer;
    };

    extraction_visitor visitor;
    boost::apply_visitor(visitor, sig);

    return visitor.m_buffer;
}

EcdsaSignatureFuture::EcdsaSignatureFuture(const std::shared_future<EcdsaSignature>& future, std::size_t bytes) :
    m_future(future), m_bytes(bytes)
{
    if (!m_future.valid()) {
        throw std::invalid_argument("EcdsaSignature future has to be valid");
    }
}

const EcdsaSignature& EcdsaSignatureFuture::get() const
{
    assert(m_future.valid());
    const EcdsaSignature& signature = m_future.get();
    assert(get_size(signature) == m_bytes);
    return signature;
}

std::size_t EcdsaSignatureFuture::size() const
{
    return m_bytes;
}

boost::optional<Signature> extract_signature(const Signature& sig)
{
    auto visitor = compose_security(
        // For ECDSA
        [&](const EcdsaSignature &sig) {
            return Signature{sig};
        },
        // For ECDSA future
        [&](const EcdsaSignatureFuture &sig) {
            return Signature{sig.get()};
        },

        // For OQS
        [&](const OqsSignature &sig) {
            return Signature{sig};
        });

    auto signature = boost::apply_visitor(visitor, sig);
    return boost::optional<Signature>(&signature != nullptr, signature);
}

} // namespace security
} // namespace vanetza
