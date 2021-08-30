#include <vanetza/security/backend_openssl.hpp>
#include <vanetza/security/openssl_wrapper.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/signature.hpp>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <cassert>

#include <iostream>
#include <boost/variant.hpp>
#include <liboqs-cpp/include/oqs_cpp.h>
#include <vanetza/security/variant_lambda_helper.hpp>

namespace vanetza
{
namespace security
{

BackendOpenSsl::BackendOpenSsl()
{
#if OPENSSL_API_COMPAT < 0x10100000L
    ERR_load_crypto_strings();
#else
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
#endif
}

Signature BackendOpenSsl::sign_data(const generic_key::PrivateKey& private_key, const ByteBuffer& data)
{
    
    auto visitor =
        compose_security(
            // For ECDSA
            [&](const ecdsa256::PrivateKey &key)
            {
                auto start = std::chrono::high_resolution_clock::now(); // start timer
                auto priv_key = internal_private_key(key);
                auto digest = calculate_digest(data);
                         

                // sign message data represented by the digest
                openssl::Signature signature{ECDSA_do_sign(digest.data(), digest.size(), priv_key)};
#if OPENSSL_API_COMPAT < 0x10100000L
                const BIGNUM* sig_r = signature->r;
                const BIGNUM* sig_s = signature->s;
#else
                const BIGNUM* sig_r = nullptr;
                const BIGNUM* sig_s = nullptr;
                ECDSA_SIG_get0(signature, &sig_r, &sig_s);
#endif

                EcdsaSignature ecdsa_signature;
                X_Coordinate_Only coordinate;

                if (sig_r && sig_s) {
                    const size_t len = field_size(PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256);

                    const auto num_bytes_s = BN_num_bytes(sig_s);
                    assert(len >= static_cast<size_t>(num_bytes_s));
                    ecdsa_signature.s.resize(len, 0x00);
                    BN_bn2bin(sig_s, ecdsa_signature.s.data() + len - num_bytes_s);

                    const auto num_bytes_r = BN_num_bytes(sig_r);
                    assert(len >= static_cast<size_t>(num_bytes_r));
                    coordinate.x.resize(len, 0x00);
                    BN_bn2bin(sig_r, coordinate.x.data() + len - num_bytes_r);
                } else {
                    throw openssl::Exception();
                }
                std::cout << "BackendOpenSslEcdsa::Sign size " << field_size(PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256) << std::endl;
                ecdsa_signature.R = std::move(coordinate);

                auto diff = std::chrono::high_resolution_clock::now() - start; // get difference
                auto msec = std::chrono::duration_cast<std::chrono::microseconds>(diff);
                //std::cout << "BackendOpenSslEcdsa::sign_data took: " << msec.count() << " microseconds" << std::endl;
                return Signature{ecdsa_signature};
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
                //std::cout << "BackendOpenSslOQS::Data size " << data.size() << std::endl;
                auto start = std::chrono::high_resolution_clock::now(); // start timer
                signature.S = signer.sign(data);
                std::cout << "BackendOpenSsl" << sig_name << "::Sign size " << signature.S.size() << std::endl;
                auto diff = std::chrono::high_resolution_clock::now() - start; // get difference
                auto msec = std::chrono::duration_cast<std::chrono::microseconds>(diff);
                //std::cout << "BackendOpenSsl" << sig_name << "::sign_data took: " << msec.count() << " microseconds" << std::endl;
                return Signature{signature};
            });

    return boost::apply_visitor(visitor, private_key);
}

bool BackendOpenSsl::verify_data(const generic_key::PublicKey& key, const ByteBuffer& data, const Signature& sig)
{
    auto digest = calculate_digest(data);
    auto visitor = compose_security(
        // For ECDSA
        [&](const EcdsaSignature &sig)
        {
            auto ecdsa_key = boost::get<ecdsa256::PublicKey>(key);
            auto pub = internal_public_key(ecdsa_key);
            openssl::Signature signature(sig);
             std::cout << "BackendOpenSslEcdsa::Verify size " << field_size(PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256) << std::endl;
            bool v_result = (ECDSA_do_verify(digest.data(), digest.size(), signature, pub) == 1);
            return v_result;
        },
        [&](const EcdsaSignatureFuture &sig)
        {
            return false; // future is optional
        },
        // For OQS
        [&](const OqsSignature &sig)
        {
            // Get the type and name of private key
            auto oqs_key = boost::get<generic_key::PublicKeyOQS>(key);
            std::string sig_name = get_string_from_algo(oqs_key.m_type);
            oqs::Signature verifier{sig_name};
            std::cout << "BackendOpenSsl" << sig_name << "::Verify size " << sig.S.size() << std::endl;
            bool v_result = verifier.verify(data, sig.S, oqs_key.pub_K);
            return v_result;
        });

    return boost::apply_visitor(visitor, sig);
}

boost::optional<Uncompressed> BackendOpenSsl::decompress_point(const EccPoint& ecc_point)
{
    struct DecompressionVisitor : public boost::static_visitor<bool>
    {
        bool operator()(const X_Coordinate_Only&)
        {
            return false;
        }

        bool operator()(const Compressed_Lsb_Y_0& p)
        {
            return decompress(p.x, 0);
        }

        bool operator()(const Compressed_Lsb_Y_1& p)
        {
            return decompress(p.x, 1);
        }

        bool operator()(const Uncompressed& p)
        {
            result = p;
            return true;
        }

        bool decompress(const ByteBuffer& x, int y_bit)
        {
            openssl::BigNumberContext ctx;
            openssl::BigNumber x_coordinate(x);
            openssl::Group group(NID_X9_62_prime256v1);
            openssl::Point point(group);
            openssl::BigNumber y_coordinate;

            result.x = x;
            result.y.resize(result.x.size());

#if OPENSSL_API_COMPAT < 0x10101000L
            EC_POINT_set_compressed_coordinates_GFp(group, point, x_coordinate, y_bit, ctx);
            EC_POINT_get_affine_coordinates_GFp(group, point, nullptr, y_coordinate, ctx);
            std::size_t y_coordinate_bytes = BN_num_bytes(y_coordinate);
            if (y_coordinate_bytes <= result.y.size()) {
                BN_bn2bin(y_coordinate, result.y.data() + (result.y.size() - y_coordinate_bytes));
                return true;
            } else {
                return false;
            }
#else
            EC_POINT_set_compressed_coordinates(group, point, x_coordinate, y_bit, ctx);
            EC_POINT_get_affine_coordinates(group, point, nullptr, y_coordinate, ctx);
            return (BN_bn2binpad(y_coordinate, result.y.data(), result.y.size()) != -1);
#endif
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

std::array<uint8_t, 32> BackendOpenSsl::calculate_digest(const ByteBuffer& data) const
{
    static_assert(SHA256_DIGEST_LENGTH == 32, "Unexpected length of SHA256 digest");

    std::array<uint8_t, 32> digest;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data.data(), data.size());
    SHA256_Final(digest.data(), &ctx);
    return digest;
}

openssl::Key BackendOpenSsl::internal_private_key(const ecdsa256::PrivateKey& generic) const
{
    openssl::Key key(NID_X9_62_prime256v1);
    openssl::BigNumber prv(generic.key);
    EC_KEY_set_private_key(key, prv);

    // OpenSSL requires public key, so we recreate it from private key
    openssl::BigNumberContext ctx;
    const EC_GROUP* group = EC_KEY_get0_group(key);
    openssl::Point pub(group);
    openssl::check(EC_POINT_mul(group, pub, prv, nullptr, nullptr, ctx));
    EC_KEY_set_public_key(key, pub);

    openssl::check(EC_KEY_check_key(key));
    return key;
}

openssl::Key BackendOpenSsl::internal_public_key(const ecdsa256::PublicKey& generic) const
{
    openssl::Key key(NID_X9_62_prime256v1);
    openssl::BigNumber x(generic.x);
    openssl::BigNumber y(generic.y);
    EC_KEY_set_public_key_affine_coordinates(key, x, y);

    openssl::check(EC_KEY_check_key(key));
    return key;
}

} // namespace security
} // namespace vanetza
