#include <vanetza/security/backend_cryptopp.hpp>
#include <vanetza/security/ecc_point.hpp>
#include <cryptopp/oids.h>
#include <algorithm>
#include <cassert>
#include <iterator>
#include <functional>
#include <iostream>
#include <boost/variant.hpp>
namespace vanetza
{
namespace security
{

using std::placeholders::_1;

BackendCryptoPP::BackendCryptoPP() :
    m_private_cache(std::bind(&BackendCryptoPP::internal_private_key, this, _1), 8),
    m_public_cache(std::bind(&BackendCryptoPP::internal_public_key, this, _1), 2048)
{
}

Signature BackendCryptoPP::sign_data(const generic_key::PrivateKey& generic_key, const ByteBuffer& data)
{
     auto start = std::chrono::high_resolution_clock::now(); // start timer
     auto visitor = generic_key::compose(
         // For ECDSA
         [&](const ecdsa256::PrivateKey &key)
         {
             return Signature{sign_data(m_private_cache[key], data)};
         },

         // For OQS
         [&](const generic_key::PrivateKeyOQS &key)
         {
             // Get the type and name of private key
            std::string sig_name = get_string_from_algo(key.m_type);
             // generic_key::PrivateKey is also in the TYPE expected i.e bytes
             // Instantiate a signature object
             oqs::Signature signer{sig_name, key.priv_K};
             
             // Sign the message
             OqsSignature signature(key.m_type);
             signature.S = signer.sign(data);
             std::cout << "Sign size " << signature.S.size() << std::endl;
             auto diff = std::chrono::high_resolution_clock::now() - start; // get difference
             auto msec = std::chrono::duration_cast<std::chrono::microseconds>(diff);
             std::cout << "BackendCryptoppOQS::sign_data took: " << msec.count() << " microseconds" << std::endl;
             return Signature{signature};
         });
     return boost::apply_visitor(visitor, generic_key);
}

EcdsaSignature BackendCryptoPP::sign_data(const PrivateKey& private_key, const ByteBuffer& data)
{
    // calculate signature
    Signer signer(private_key);
    ByteBuffer signature(signer.MaxSignatureLength(), 0x00);
    auto signature_length = signer.SignMessage(m_prng, data.data(), data.size(), signature.data());
    signature.resize(signature_length);

    auto signature_delimiter = signature.begin();
    std::advance(signature_delimiter, 32);

    EcdsaSignature ecdsa_signature;
    // set R
    X_Coordinate_Only coordinate;
    coordinate.x = ByteBuffer(signature.begin(), signature_delimiter);
    ecdsa_signature.R = std::move(coordinate);
    // set s
    ByteBuffer trailer_field_buffer(signature_delimiter, signature.end());
    ecdsa_signature.s = std::move(trailer_field_buffer);

    return ecdsa_signature;
}

bool BackendCryptoPP::verify_data(const generic_key::PublicKey& generic_key, const ByteBuffer& msg, const Signature& sig)
{
    const ByteBuffer sigbuf = extract_signature_buffer(sig);

    auto visitor = generic_key::compose(
        // For ECDSA
        [&](const EcdsaSignature &sig)
        {
            auto ecdsa_key = boost::get<ecdsa256::PublicKey>(generic_key);
            auto pub = internal_public_key(ecdsa_key);
            return verify_data(m_public_cache[ecdsa_key], msg, sigbuf);
        },
        [&](const EcdsaSignatureFuture &sig)
        {
            return false; // future is optional
        },
        // For OQS
        [&](const OqsSignature &sig)
        {
            // Get the type and name of private key
            auto oqs_key = boost::get<generic_key::PublicKeyOQS>(generic_key);
            std::string sig_name = get_string_from_algo(oqs_key.m_type);
            oqs::Signature verifier{sig_name};
            return verifier.verify(msg, sigbuf, oqs_key.pub_K);
        });

    return boost::apply_visitor(visitor, sig);
}

bool BackendCryptoPP::verify_data(const PublicKey& public_key, const ByteBuffer& msg, const ByteBuffer& sig)
{
    Verifier verifier(public_key);
    return verifier.VerifyMessage(msg.data(), msg.size(), sig.data(), sig.size());
}


boost::optional<Uncompressed> BackendCryptoPP::decompress_point(const EccPoint& ecc_point)
{
    struct DecompressionVisitor : public boost::static_visitor<bool>
    {
        bool operator()(const X_Coordinate_Only&)
        {
            return false;
        }

        bool operator()(const Compressed_Lsb_Y_0& p)
        {
            decompress(p.x, 0x02);
            return true;
        }

        bool operator()(const Compressed_Lsb_Y_1& p)
        {
            decompress(p.x, 0x03);
            return true;
        }

        bool operator()(const Uncompressed& p)
        {
            result = p;
            return true;
        }

        void decompress(const ByteBuffer& x, ByteBuffer::value_type type)
        {
            ByteBuffer compact;
            compact.reserve(x.size() + 1);
            compact.push_back(type);
            std::copy(x.begin(), x.end(), std::back_inserter(compact));

            BackendCryptoPP::Point point;
            CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> group(CryptoPP::ASN1::secp256r1());
            group.GetCurve().DecodePoint(point, compact.data(), compact.size());

            result.x = x;
            result.y.resize(result.x.size());
            point.y.Encode(result.y.data(), result.y.size());
        }

        Uncompressed result;
    };

    DecompressionVisitor visitor;
    if (boost::apply_visitor(visitor, ecc_point)) {
        return visitor.result;
    } else {
        return boost::none;
    }
}

generic_key::KeyPair BackendCryptoPP::generate_key_pair(const std::string& sig_key_type)
{
    generic_key::KeyPair g_kp;
    // For ECDSA
    PublicKeyAlgorithm type = get_algo_from_string(sig_key_type);
    switch (type)
    { 
    case PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256:
    {
        ecdsa256::KeyPair kp;
        auto private_key = generate_private_key();
        auto& private_exponent = private_key.GetPrivateExponent();
        assert(kp.private_key.key.size() >= private_exponent.ByteCount());
        private_exponent.Encode(kp.private_key.key.data(), kp.private_key.key.size());

        auto public_key = generate_public_key(private_key);
        auto& public_element = public_key.GetPublicElement();
        assert(kp.public_key.x.size() >= public_element.x.ByteCount());
        assert(kp.public_key.y.size() >= public_element.y.ByteCount());
        public_element.x.Encode(kp.public_key.x.data(), kp.public_key.x.size());
        public_element.y.Encode(kp.public_key.y.data(), kp.public_key.y.size());

        g_kp = generic_key::KeyPair{std::move(kp)};
        break;
    }
    case PublicKeyAlgorithm::ECIES_NISTP256: 
    case PublicKeyAlgorithm::UNKNOWN:
        assert(false && "Unknown signature key type");
    // For OQS
    default:
    {
        generic_key::KeyPairOQS kp;
        kp.private_key.m_type = type;
        kp.public_key.m_type = kp.private_key.m_type;

        oqs::Signature signer{sig_key_type};

        kp.public_key.pub_K = signer.generate_keypair();
        kp.private_key.priv_K = signer.export_secret_key();
        g_kp = generic_key::KeyPair{std::move(kp)};
        break;
    }
    };
    return g_kp;
}

BackendCryptoPP::PrivateKey BackendCryptoPP::generate_private_key()
{
    CryptoPP::OID oid(CryptoPP::ASN1::secp256r1());
    PrivateKey private_key;
    private_key.Initialize(m_prng, oid);
    assert(private_key.Validate(m_prng, 3));
    return private_key;
}

BackendCryptoPP::PublicKey BackendCryptoPP::generate_public_key(const PrivateKey& private_key)
{
    PublicKey public_key;
    private_key.MakePublicKey(public_key);
    assert(public_key.Validate(m_prng, 3));
    return public_key;
}

BackendCryptoPP::PublicKey BackendCryptoPP::internal_public_key(const ecdsa256::PublicKey& generic)
{
    CryptoPP::Integer x { generic.x.data(), generic.x.size() };
    CryptoPP::Integer y { generic.y.data(), generic.y.size() };
    CryptoPP::ECP::Point q { x, y };

    BackendCryptoPP::PublicKey pub;
    pub.Initialize(CryptoPP::ASN1::secp256r1(), q);
    assert(pub.Validate(m_prng, 3));
    return pub;
}

BackendCryptoPP::PrivateKey BackendCryptoPP::internal_private_key(const ecdsa256::PrivateKey& generic)
{
    PrivateKey key;
    CryptoPP::Integer integer { generic.key.data(), generic.key.size() };
    key.Initialize(CryptoPP::ASN1::secp256r1(), integer);
    return key;
}

} // namespace security
} // namespace vanetza
