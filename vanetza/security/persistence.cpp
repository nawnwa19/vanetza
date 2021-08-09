#include "persistence.hpp"
#include <boost/variant/get.hpp>
#include <cryptopp/eccrypto.h>
#include <cryptopp/files.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <fstream>

namespace vanetza
{
namespace security
{

generic_key::KeyPair load_private_key_from_file(const std::string& key_path,const std::string& sig_key_type)
{
    generic_key::KeyPair result;
    namespace vs = vanetza::security;
    vs::PublicKeyAlgorithm type = vs::get_algo_from_string(sig_key_type);
    switch (type) {
        case vs::PublicKeyAlgorithm::ECIES_NISTP256:
        case vs::PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256: {
            CryptoPP::AutoSeededRandomPool rng;

            CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey
                private_key;
            CryptoPP::FileSource key_file(key_path.c_str(), true);
            private_key.Load(key_file);

            if (!private_key.Validate(rng, 3)) {
                throw std::runtime_error("Private key validation failed");
            }

            ecdsa256::KeyPair key_pair;

            auto& private_exponent = private_key.GetPrivateExponent();
            private_exponent.Encode(key_pair.private_key.key.data(),
                                    key_pair.private_key.key.size());

            CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey
                public_key;
            private_key.MakePublicKey(public_key);

            auto& public_element = public_key.GetPublicElement();
            public_element.x.Encode(key_pair.public_key.x.data(),
                                    key_pair.public_key.x.size());
            public_element.y.Encode(key_pair.public_key.y.data(),
                                    key_pair.public_key.y.size());

            result = generic_key::KeyPair{std::move(key_pair)};
            break;
        }
        case vs::PublicKeyAlgorithm::UNKNOWN:
            break;
        default: {  // For all OQS types
            generic_key::KeyPairOQS key_pair;
            std::ifstream key_src(key_path, std::ios::binary);
            
            if (key_src.is_open()) { 
                vanetza::InputArchive ar(key_src);
                vs::generic_key::deserialize(ar, key_pair, type);
                result = generic_key::KeyPair{std::move(key_pair)};
                key_src.close();
            } else
                std::cout << "Unable to open file" << std::endl;
            break;
        }
    }
    return result;
}

PublicKey load_public_key_from_file(const std::string& key_path)
{
    PublicKey public_key;

    std::ifstream key_src;
    key_src.open(key_path, std::ios::in | std::ios::binary);
    vanetza::InputArchive key_archive(key_src);
    deserialize(key_archive, public_key);

    return public_key;
}

void save_public_key_to_file(const std::string& key_path, const PublicKey& public_key)
{
    std::ofstream dest;
    dest.open(key_path.c_str(), std::ios::out | std::ios::binary);

    OutputArchive archive(dest);
    serialize(archive, public_key);
}

Certificate load_certificate_from_file(const std::string& certificate_path)
{
    Certificate certificate;

    std::ifstream certificate_src;
    certificate_src.open(certificate_path, std::ios::in | std::ios::binary);
    vanetza::InputArchive certificate_archive(certificate_src);
    deserialize(certificate_archive, certificate);

    return certificate;
}

void save_certificate_to_file(const std::string& certificate_path, const Certificate& certificate)
{
    std::ofstream dest;
    dest.open(certificate_path.c_str(), std::ios::out | std::ios::binary);

    OutputArchive archive(dest);
    serialize(archive, certificate);
}

} // namespace security
} // namespace vanetza
