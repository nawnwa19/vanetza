#include <vanetza/security/exception.hpp>
#include <vanetza/security/public_key.hpp>
#include <boost/variant/apply_visitor.hpp>
#include <boost/variant/static_visitor.hpp>
#include <string>
#include <vanetza/common/enum_helper.hpp>
#include <liboqs-cpp/include/oqs_cpp.h>

namespace vanetza
{
namespace security
{

PublicKeyAlgorithm get_type(const PublicKey& key)
{
    struct public_key_visitor : public boost::static_visitor<PublicKeyAlgorithm>
    {
        PublicKeyAlgorithm operator()(const ecdsa_nistp256_with_sha256& ecdsa)
        {
            return PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256;
        }
        PublicKeyAlgorithm operator()(const ecies_nistp256& ecies)
        {
            return PublicKeyAlgorithm::ECIES_NISTP256;
        }
        PublicKeyAlgorithm operator()(const oqs_nist& oqs)
        {
            return oqs.type;
        }

    };

    public_key_visitor visit;
    return boost::apply_visitor(visit, key);
}

void serialize(OutputArchive& ar, const PublicKey& key)
{
    struct public_key_visitor : public boost::static_visitor<>
    {
        public_key_visitor(OutputArchive& ar, PublicKeyAlgorithm algo) :
            m_archive(ar), m_algo(algo)
        {
        }
        void operator()(const ecdsa_nistp256_with_sha256& ecdsa)
        {
            serialize(m_archive, ecdsa.public_key, m_algo);
        }
        void operator()(const ecies_nistp256& ecies)
        {
            serialize(m_archive, ecies.supported_symm_alg);
            serialize(m_archive, ecies.public_key, m_algo);
        }
        void operator()(const oqs_nist& oqs)
        {
            serialize(m_archive, oqs.public_key, oqs.type);
        }
        OutputArchive& m_archive;
        PublicKeyAlgorithm m_algo;
    };

    PublicKeyAlgorithm type = get_type(key);
    serialize(ar, type);
    public_key_visitor visit(ar, type);
    boost::apply_visitor(visit, key);
}

std::size_t field_size(PublicKeyAlgorithm algo)
{
    size_t size = 0;
    switch (algo) {
        case PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256:
            size = 32;
            break;
        case PublicKeyAlgorithm::ECIES_NISTP256:
            size = 32;
            break;
        case PublicKeyAlgorithm::DILITHIUM2:
            size = 1312;
            break;
        case PublicKeyAlgorithm::DILITHIUM3:
            size = 1952;
            break;
        case PublicKeyAlgorithm::DILITHIUM5:
            size = 2592;
            break;
        case PublicKeyAlgorithm::FALCON_512:
            size = 897;
            break;
        case PublicKeyAlgorithm::FALCON_1024:
            size = 1793;
            break;
        default:
            assert(false && "Unknown signature algorithm");
    }
    return size;
}

std::size_t field_size_signature(PublicKeyAlgorithm algo)
{
    size_t size = 0;
    switch (algo) {
        case PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256:
            size = 32;
            break;
        case PublicKeyAlgorithm::ECIES_NISTP256:
            size = 32;
            break;
        case PublicKeyAlgorithm::DILITHIUM2:
            size = 2420;
            break;
        case PublicKeyAlgorithm::DILITHIUM3:
            size = 3293;
            break;
        case PublicKeyAlgorithm::DILITHIUM5:
            size = 4595;
            break;
        case PublicKeyAlgorithm::FALCON_512:
            size = 666;
            break;
        case PublicKeyAlgorithm::FALCON_1024:
            size = 1280;
            break;
        default:
            assert(false && "Unknown signature algorithm");
    }
    return size;
}

std::size_t field_size_private(PublicKeyAlgorithm algo)
{
    size_t size = 0;
    switch (algo) {
        case PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256:
            size = 32;
            break;
        case PublicKeyAlgorithm::ECIES_NISTP256:
            size = 32;
            break;
        case PublicKeyAlgorithm::DILITHIUM2:
            size = 2528;
            break;
        case PublicKeyAlgorithm::DILITHIUM3:
            size = 4000;
            break;
        case PublicKeyAlgorithm::DILITHIUM5:
            size = 4864;
            break;
        case PublicKeyAlgorithm::FALCON_512:
            size = 1281;
            break;
        case PublicKeyAlgorithm::FALCON_1024:
            size = 2305;
            break;
        default:
            assert(false && "Unknown signature algorithm");
    }
    return size;
}


std::size_t field_size(SymmetricAlgorithm algo)
{
    size_t size = 0;
    switch (algo) {
        case SymmetricAlgorithm::AES128_CCM:
            size = 16;
            break;
        default:
            throw deserialization_error("Unknown SymmetricAlgorithm");
            break;
    }
    return size;
}

size_t deserialize(InputArchive& ar, PublicKey& key)
{
    PublicKeyAlgorithm type;
    deserialize(ar, type);
    switch (type) {
        case PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256: {
            ecdsa_nistp256_with_sha256 ecdsa;
            deserialize(ar, ecdsa.public_key, PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256);
            key = ecdsa;
            break;
        }
        case PublicKeyAlgorithm::ECIES_NISTP256: {
            ecies_nistp256 ecies;
            deserialize(ar, ecies.supported_symm_alg);
            deserialize(ar, ecies.public_key, PublicKeyAlgorithm::ECIES_NISTP256);
            key = ecies;
            break;
        }
        case PublicKeyAlgorithm::UNKNOWN:
            assert(false && "Unknown PublicKeyAlgorithm");
        default: {
            oqs_nist oqs;
            oqs.type = type;
            deserialize(ar, oqs.public_key,oqs.type);
            key = oqs;
            break;
        }
    }
    return get_size(key);
}

size_t get_size(const PublicKey& key)
{
    size_t size = sizeof(PublicKeyAlgorithm);
    struct publicKey_visitor : public boost::static_visitor<size_t>
    {
        size_t operator()(ecdsa_nistp256_with_sha256 key)
        {
            return get_size(key.public_key);
        }
        size_t operator()(ecies_nistp256 key)
        {
            return get_size(key.public_key) + sizeof(key.supported_symm_alg);
        }
        size_t operator()(oqs_nist key)
        {
            return get_size(key.public_key);
        }

    };
    publicKey_visitor visit;
    size += boost::apply_visitor(visit, key);
    return size;
}

// String and enum to and from conversion
template <>
char const* enumStrings<PublicKeyAlgorithm>::data[] = {
    "ecdsa256",   "ecies256",   "Dilithium2", "Dilithium3",
    "Dilithium5", "Falcon-512", "Falcon-1024", "Unknown"};

PublicKeyAlgorithm get_algo_from_string(const std::string &sig_key_type)
{
    PublicKeyAlgorithm pka;
    std::stringstream ss(sig_key_type);
    ss >> enumFromString(pka);
    return pka;
}

std::string get_string_from_algo(const PublicKeyAlgorithm &sig_key_type)
{
     std::stringstream ss;
     ss << enumToString(sig_key_type);
     return ss.str();
}





} // namespace security
} // namespace vanetza
