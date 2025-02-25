#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/naive_certificate_provider.hpp>
#include <vanetza/security/payload.hpp>
#include <vanetza/security/secured_message.hpp>
#include <vanetza/security/signature.hpp>
#include <vanetza/security/variant_lambda_helper.hpp>
#include <chrono>

namespace vanetza
{
namespace security
{

NaiveCertificateProvider::NaiveCertificateProvider(const Runtime& rt,const std::string& sig_type, bool hybrid = false) :
    m_runtime(rt),
    m_signature_key_type(sig_type),
    m_hybrid(hybrid),
    m_own_key_pair(m_crypto_backend.generate_key_pair(sig_type)),
    m_own_outer_key_pair(m_crypto_backend.generate_key_pair("ecdsa256")),
    m_own_certificate(generate_authorization_ticket()) {
    }

const Certificate& NaiveCertificateProvider::own_certificate()
{
    // renew certificate if necessary
    for (auto& validity_restriction : m_own_certificate.validity_restriction) {
        auto start_and_end = boost::get<StartAndEndValidity>(&validity_restriction);
        auto renewal_deadline = convert_time32(m_runtime.now() + std::chrono::hours(1));
        if (start_and_end && start_and_end->end_validity < renewal_deadline) {
            m_own_certificate = generate_authorization_ticket();
            break;
        }
    }

    return m_own_certificate;
}

std::list<Certificate> NaiveCertificateProvider::own_chain()
{
    static const std::list<Certificate> chain = { aa_certificate() };
    return chain;
}

const generic_key::PrivateKey& NaiveCertificateProvider::own_private_key()
{
    auto visitor = compose_security(
        // For ECDSA
        [&](const ecdsa256::KeyPair& key_pair) {
            return generic_key::PrivateKey{key_pair.private_key};
        },

        // For OQS
        [&](const generic_key::KeyPairOQS& key_pair) {
            if (m_hybrid) {
                return own_private_outer_key();
            } else {
                return generic_key::PrivateKey{key_pair.private_key};
            }
        });

    static const auto key =  boost::apply_visitor(visitor, m_own_key_pair);
    return key;
}

const generic_key::PrivateKey& NaiveCertificateProvider::own_private_outer_key() {
    static const auto outer_key = generic_key::PrivateKey{
        boost::get<ecdsa256::KeyPair>(m_own_outer_key_pair).private_key};
    return outer_key;
}

const generic_key::KeyPair& NaiveCertificateProvider::aa_key_pair()
{
    static const generic_key::KeyPair aa_key_pair = m_crypto_backend.generate_key_pair(m_signature_key_type);
    return aa_key_pair;
}

const generic_key::KeyPair& NaiveCertificateProvider::aa_outer_key_pair()
{
    static const generic_key::KeyPair aa_outer_key_pair = m_crypto_backend.generate_key_pair("ecdsa256");
    return aa_outer_key_pair;
}

const generic_key::KeyPair& NaiveCertificateProvider::root_key_pair()
{
    static const generic_key::KeyPair root_key_pair = m_crypto_backend.generate_key_pair(m_signature_key_type);
    return root_key_pair;
}

const generic_key::KeyPair& NaiveCertificateProvider::root_outer_key_pair()
{
    static const generic_key::KeyPair root_outer_key_pair = m_crypto_backend.generate_key_pair("ecdsa256");
    return root_outer_key_pair;
}

const Certificate& NaiveCertificateProvider::aa_certificate()
{
    static const std::string aa_subject("Naive Authorization CA");
    static const Certificate aa_certificate = generate_aa_certificate(aa_subject);

    return aa_certificate;
}

const Certificate& NaiveCertificateProvider::root_certificate()
{
    static const std::string root_subject("Naive Root CA");
    static const Certificate root_certificate = generate_root_certificate(root_subject);

    return root_certificate;
}

Certificate NaiveCertificateProvider::generate_authorization_ticket()
{
    // create certificate
    Certificate certificate;
    if (m_hybrid) certificate.version = 3;

    // section 6.1 in TS 103 097 v1.2.1
    certificate.signer_info = calculate_hash(aa_certificate());

    // section 6.3 in TS 103 097 v1.2.1
    certificate.subject_info.subject_type = SubjectType::Authorization_Ticket;
    // section 7.4.2 in TS 103 097 v1.2.1, subject_name implicit empty

    // set assurance level
    certificate.subject_attributes.push_back(SubjectAssurance(0x00));

    certificate.add_permission(aid::CA, ByteBuffer({ 1, 0, 0 }));
    certificate.add_permission(aid::DEN, ByteBuffer({ 1, 0xff, 0xff, 0xff}));
    certificate.add_permission(aid::GN_MGMT, ByteBuffer({})); // required for beacons
    certificate.add_permission(aid::IPV6_ROUTING, ByteBuffer({})); // required for routing tests

    // section 7.4.1 in TS 103 097 v1.2.1
    // set subject attributes
    // set the verification_key
    auto visitor = compose_security(
        // For ECDSA
        [&](const ecdsa256::KeyPair &key_pair)
        {
            Uncompressed coordinates;
            coordinates.x.assign(key_pair.public_key.x.begin(), key_pair.public_key.x.end());
            coordinates.y.assign(key_pair.public_key.y.begin(), key_pair.public_key.y.end());
            EccPoint ecc_point = coordinates;
            ecdsa_nistp256_with_sha256 ecdsa;
            ecdsa.public_key = ecc_point;
            VerificationKey verification_key;
            verification_key.key = ecdsa;
            certificate.subject_attributes.push_back(verification_key);
        },

        // For OQS
        [&](const generic_key::KeyPairOQS &key_pair) {
            oqs_nist oqs_key;
            oqs_key.type = key_pair.public_key.m_type;
            oqs_key.public_key.K = key_pair.public_key.pub_K;
            VerificationKey verification_key;
            verification_key.key = oqs_key;
            certificate.subject_attributes.push_back(verification_key);
        });

    if (m_hybrid)
        boost::apply_visitor(visitor, m_own_outer_key_pair);
    else
        boost::apply_visitor(visitor, m_own_key_pair);

    // section 6.7 in TS 103 097 v1.2.1
    // set validity restriction
    StartAndEndValidity start_and_end;
    start_and_end.start_validity = convert_time32(m_runtime.now() - std::chrono::hours(1));
    start_and_end.end_validity = convert_time32(m_runtime.now() + std::chrono::hours(23));
    certificate.validity_restriction.push_back(start_and_end);

    sign_authorization_ticket(certificate);

    return certificate;
}

void NaiveCertificateProvider::sign_authorization_ticket(Certificate& certificate)
{
    sort(certificate);

    auto visitor = compose_security(
        // For ECDSA
        [&](const ecdsa256::KeyPair& key_pair) {
            ByteBuffer data_buffer = convert_for_signing(certificate);
            certificate.signature =
                m_openssl_backend.sign_data(key_pair.private_key, data_buffer);
        },
        // For OQS
        [&](const generic_key::KeyPairOQS& key_pair) {
            if (m_hybrid) {
                certificate.hybrid_signature_extension.hybrid_key.K =
                    key_pair.public_key.pub_K;
                certificate.hybrid_signature_extension.hybrid_sig.sig_type =
                    key_pair.public_key.m_type;
                size_t sig_size =
                    field_size_signature(key_pair.public_key.m_type);

                // Resizing the extension inner signature and setting all bits to 0
                certificate.hybrid_signature_extension.hybrid_sig.S.resize(
                    sig_size);
                memset(
                    certificate.hybrid_signature_extension.hybrid_sig.S.data(),
                    0, sig_size);

                ByteBuffer data_buffer = convert_for_signing(certificate);

                // Hybrid: Signing including zeroed extension using OQS
                Signature tmp = m_openssl_backend.sign_data(
                    key_pair.private_key, data_buffer);

                certificate.hybrid_signature_extension.hybrid_sig =
                    boost::get<OqsSignature>(tmp);

                // Hybrid: Signing including extension using ECDSA
                auto outer_key_pair =
                    boost::get<ecdsa256::KeyPair>(aa_outer_key_pair());
                ByteBuffer outer_data_buffer = convert_for_signing(certificate);
                certificate.signature = m_openssl_backend.sign_data(
                    outer_key_pair.private_key, outer_data_buffer);
            } else {
                ByteBuffer data_buffer = convert_for_signing(certificate);
                // OQS: Signing the all the fields
                certificate.signature = m_openssl_backend.sign_data(
                    key_pair.private_key, data_buffer);
            }
        });
    boost::apply_visitor(visitor, aa_key_pair());
}

Certificate NaiveCertificateProvider::generate_aa_certificate(const std::string& subject_name)
{
    // create certificate
    Certificate certificate;
    if (m_hybrid) certificate.version = 3;

    // section 6.1 in TS 103 097 v1.2.1
    certificate.signer_info = calculate_hash(root_certificate());

    // section 6.3 in TS 103 097 v1.2.1
    certificate.subject_info.subject_type = SubjectType::Authorization_Authority;

    // section 7.4.2 in TS 103 097 v1.2.1
    std::vector<unsigned char> subject(subject_name.begin(), subject_name.end());
    certificate.subject_info.subject_name = subject;

    // section 6.6 in TS 103 097 v1.2.1 - levels currently undefined
    certificate.subject_attributes.push_back(SubjectAssurance(0x00));

    certificate.add_permission(aid::CA);
    certificate.add_permission(aid::DEN);
    certificate.add_permission(aid::GN_MGMT); // required for beacons
    certificate.add_permission(aid::IPV6_ROUTING); // required for routing tests

    // section 7.4.1 in TS 103 097 v1.2.1
    // set subject attributes
    // set the verification_key
    auto visitor1 = compose_security(
        // For ECDSA
        [&](const ecdsa256::KeyPair &key_pair)
        {
            Uncompressed coordinates;
            coordinates.x.assign(key_pair.public_key.x.begin(), key_pair.public_key.x.end());
            coordinates.y.assign(key_pair.public_key.y.begin(), key_pair.public_key.y.end());
            EccPoint ecc_point = coordinates;
            ecdsa_nistp256_with_sha256 ecdsa;
            ecdsa.public_key = ecc_point;
            VerificationKey verification_key;
            verification_key.key = ecdsa;
            certificate.subject_attributes.push_back(verification_key);
        },

        // For OQS
        [&](const generic_key::KeyPairOQS &key_pair)
        {
            oqs_nist oqs_key;
            oqs_key.type = key_pair.public_key.m_type;
            oqs_key.public_key.K = key_pair.public_key.pub_K;
            VerificationKey verification_key;
            verification_key.key = oqs_key;
            certificate.subject_attributes.push_back(verification_key);
        });

    if (m_hybrid)
        boost::apply_visitor(visitor1, aa_outer_key_pair());
    else
        boost::apply_visitor(visitor1, aa_key_pair());

    // section 6.7 in TS 103 097 v1.2.1
    // set validity restriction
    StartAndEndValidity start_and_end;
    start_and_end.start_validity = convert_time32(m_runtime.now() - std::chrono::hours(1));
    start_and_end.end_validity = convert_time32(m_runtime.now() + std::chrono::hours(23));
    certificate.validity_restriction.push_back(start_and_end);

    sort(certificate);

    // set signature
    auto visitor2 = compose_security(
        // For ECDSA
        [&](const ecdsa256::KeyPair& key_pair) {
            ByteBuffer data_buffer = convert_for_signing(certificate);
            certificate.signature =
                m_openssl_backend.sign_data(key_pair.private_key, data_buffer);
        },
        // For OQS or Hybrid
        [&](const generic_key::KeyPairOQS& key_pair) {
            if (m_hybrid) {
                certificate.hybrid_signature_extension.hybrid_key.K =
                    key_pair.public_key.pub_K;
                certificate.hybrid_signature_extension.hybrid_sig.sig_type =
                    key_pair.public_key.m_type;
                size_t sig_size =
                    field_size_signature(key_pair.public_key.m_type);

                // Resizing the extension inner signature and setting all bits
                // to 0
                certificate.hybrid_signature_extension.hybrid_sig.S.resize(
                    sig_size);
                memset(
                    certificate.hybrid_signature_extension.hybrid_sig.S.data(),
                    0, sig_size);

                ByteBuffer data_buffer = convert_for_signing(certificate);

                // Hybrid: Signing including zeroed extension using OQS
                Signature tmp = m_openssl_backend.sign_data(
                    key_pair.private_key, data_buffer);

                certificate.hybrid_signature_extension.hybrid_sig =
                    boost::get<OqsSignature>(tmp);

                // Hybrid: Signing including extension using ECDSA
                auto outer_key_pair =
                    boost::get<ecdsa256::KeyPair>(root_outer_key_pair());
                ByteBuffer outer_data_buffer = convert_for_signing(certificate);
                certificate.signature = m_openssl_backend.sign_data(
                    outer_key_pair.private_key, outer_data_buffer);
            } else {
                ByteBuffer data_buffer = convert_for_signing(certificate);
                // OQS: Signing the all the fields
                certificate.signature = m_openssl_backend.sign_data(
                    key_pair.private_key, data_buffer);
            }
        });
    boost::apply_visitor(visitor2, root_key_pair());
    return certificate;
}

Certificate NaiveCertificateProvider::generate_root_certificate(const std::string& subject_name)
{
    // create certificate
    Certificate certificate;
    if (m_hybrid) certificate.version = 3;
    
    // section 6.1 in TS 103 097 v1.2.1
    certificate.signer_info = nullptr; /* self */

    // section 6.3 in TS 103 097 v1.2.1
    certificate.subject_info.subject_type = SubjectType::Root_CA;

    // section 7.4.2 in TS 103 097 v1.2.1
    std::vector<unsigned char> subject(subject_name.begin(), subject_name.end());
    certificate.subject_info.subject_name = subject;

    // section 6.6 in TS 103 097 v1.2.1 - levels currently undefined
    certificate.subject_attributes.push_back(SubjectAssurance(0x00));

    certificate.add_permission(aid::CA);
    certificate.add_permission(aid::DEN);
    certificate.add_permission(aid::GN_MGMT); // required for beacons
    certificate.add_permission(aid::IPV6_ROUTING); // required for routing tests

    // section 7.4.1 in TS 103 097 v1.2.1
    // set subject attributes
    // set the verification_key
    auto visitor1 = compose_security(
        // For ECDSA
        [&](const ecdsa256::KeyPair &key_pair)
        {
            Uncompressed coordinates;
            coordinates.x.assign(key_pair.public_key.x.begin(), key_pair.public_key.x.end());
            coordinates.y.assign(key_pair.public_key.y.begin(), key_pair.public_key.y.end());
            EccPoint ecc_point = coordinates;
            ecdsa_nistp256_with_sha256 ecdsa;
            ecdsa.public_key = ecc_point;
            VerificationKey verification_key;
            verification_key.key = ecdsa;
            certificate.subject_attributes.push_back(verification_key);
        },

        // For OQS
        [&](const generic_key::KeyPairOQS &key_pair)
        {
            oqs_nist oqs_key;
            oqs_key.type = key_pair.public_key.m_type;
            oqs_key.public_key.K = key_pair.public_key.pub_K;
            VerificationKey verification_key;
            verification_key.key = oqs_key;
            certificate.subject_attributes.push_back(verification_key);
        });

    if(m_hybrid)
        boost::apply_visitor(visitor1, root_outer_key_pair());
    else
        boost::apply_visitor(visitor1, root_key_pair());

    // section 6.7 in TS 103 097 v1.2.1
    // set validity restriction
    StartAndEndValidity start_and_end;
    start_and_end.start_validity = convert_time32(m_runtime.now() - std::chrono::hours(1));
    start_and_end.end_validity = convert_time32(m_runtime.now() + std::chrono::hours(365 * 24));
    certificate.validity_restriction.push_back(start_and_end);

    sort(certificate);

    // set signature
    auto visitor2 = compose_security(
        // For ECDSA
        [&](const ecdsa256::KeyPair& key_pair) {
            ByteBuffer data_buffer = convert_for_signing(certificate);
            certificate.signature = m_openssl_backend.sign_data(
                key_pair.private_key, data_buffer);
        },
        // For OQS or Hybrid
        [&](const generic_key::KeyPairOQS& key_pair) {
            if (m_hybrid) {
                certificate.hybrid_signature_extension.hybrid_key.K =
                    key_pair.public_key.pub_K;
                certificate.hybrid_signature_extension.hybrid_sig.sig_type =
                    key_pair.public_key.m_type;
                size_t sig_size =
                    field_size_signature(key_pair.public_key.m_type);

                // Resizing the extension inner signature and setting all bits to 0
                certificate.hybrid_signature_extension.hybrid_sig.S.resize(
                    sig_size);
                memset(
                    certificate.hybrid_signature_extension.hybrid_sig.S.data(),
                    0, sig_size);

                ByteBuffer data_buffer = convert_for_signing(certificate);

                // Hybrid: Signing including zeroed extension using OQS
                Signature tmp = m_openssl_backend.sign_data(
                    key_pair.private_key, data_buffer);

                certificate.hybrid_signature_extension.hybrid_sig =
                    boost::get<OqsSignature>(tmp);

                // Hybrid: Signing including extension using ECDSA
                auto outer_key_pair =
                    boost::get<ecdsa256::KeyPair>(root_outer_key_pair());
                ByteBuffer outer_data_buffer = convert_for_signing(certificate);
                certificate.signature = m_openssl_backend.sign_data(
                    outer_key_pair.private_key, outer_data_buffer);
            } else {
                ByteBuffer data_buffer = convert_for_signing(certificate);
                // OQS: Signing the all the fields
                certificate.signature = m_openssl_backend.sign_data(
                    key_pair.private_key, data_buffer);
            }       
            
        });
    boost::apply_visitor(visitor2, root_key_pair());

    return certificate;
}

} // namespace security
} // namespace vanetza
