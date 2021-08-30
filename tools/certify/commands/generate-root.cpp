#include "generate-root.hpp"
#include <boost/program_options.hpp>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <vanetza/common/clock.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/backend_openssl.hpp>
#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/persistence.hpp>
#include <vanetza/security/subject_attribute.hpp>
#include <vanetza/security/subject_info.hpp>
#include <vanetza/security/variant_lambda_helper.hpp>

namespace aid = vanetza::aid;
namespace po = boost::program_options;
using namespace vanetza::security;
GenerateRootCommand::GenerateRootCommand(const std::string& sig_key_type,
                                         bool hybrid)
    : m_signature_key_type(sig_key_type), m_hybrid(hybrid) {}

bool GenerateRootCommand::parse(const std::vector<std::string>& opts)
{
    po::options_description desc("Available options");
    desc.add_options()
        ("help", "Print out available options.")
        ("output", po::value<std::string>(&output)->required(), "Output file.")
        ("subject-key", po::value<std::string>(&subject_key_path)->required(), "Private key file.")
        ("outer-subject-key", po::value<std::string>(&outer_subject_key_path), "Hybrid outer key file.")
        ("subject-name", po::value<std::string>(&subject_name)->default_value("Hello World Root-CA"), "Subject name.")
        ("days", po::value<int>(&validity_days)->default_value(365), "Validity in days.")
        ("aid", po::value<std::vector<unsigned> >(&aids)->multitoken(), "Allowed ITS-AIDs to restrict permissions, defaults to 36 (CA) and 37 (DEN) if empty.")
    ;

    po::positional_options_description pos;
    pos.add("output", 1);

    po::variables_map vm;
    po::store(po::command_line_parser(opts).options(desc).positional(pos).run(), vm);

    if (vm.count("help")) {
        std::cerr << desc << std::endl;

        return false;
    }

    try {
        po::notify(vm);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl << std::endl << desc << std::endl;

        return false;
    }

    return true;
}

int GenerateRootCommand::execute()
{
    BackendOpenSsl openssl_backend;

    std::cout << "Loading key... ";
    auto subject_key = load_private_key_from_file(subject_key_path,m_signature_key_type);
    generic_key::KeyPair outer_subject_key;
    std::cout << "OK" << std::endl;

    auto time_now = vanetza::Clock::at(boost::posix_time::microsec_clock::universal_time());

    // create certificate
    Certificate certificate;
    if (m_hybrid) certificate.version = 3;

    std::list<IntX> certificate_aids;

    if (aids.size()) {
        for (unsigned aid : aids) {
            certificate_aids.push_back(IntX(aid));
        }
    } else {
        certificate_aids.push_back(IntX(aid::CA));
        certificate_aids.push_back(IntX(aid::DEN));
    }
    certificate.subject_attributes.push_back(certificate_aids);

    // section 6.1 in TS 103 097 v1.2.1
    certificate.signer_info = nullptr; /* self */

    // section 6.3 in TS 103 097 v1.2.1
    certificate.subject_info.subject_type = SubjectType::Root_CA;

    // section 7.4.2 in TS 103 097 v1.2.1
    std::vector<unsigned char> subject(subject_name.begin(), subject_name.end());
    certificate.subject_info.subject_name = subject;

    // section 6.6 in TS 103 097 v1.2.1 - levels currently undefined
    certificate.subject_attributes.push_back(SubjectAssurance(0x00));

    // section 7.4.1 in TS 103 097 v1.2.1
    // set subject attributes
    // set the verification_key
    auto visitor1 = compose_security(
        // For ECDSA
        [&](const ecdsa256::KeyPair& subject_key) {
            Uncompressed coordinates;
            coordinates.x.assign(subject_key.public_key.x.begin(),
                                 subject_key.public_key.x.end());
            coordinates.y.assign(subject_key.public_key.y.begin(),
                                 subject_key.public_key.y.end());
            EccPoint ecc_point = coordinates;
            ecdsa_nistp256_with_sha256 ecdsa;
            ecdsa.public_key = ecc_point;
            VerificationKey verification_key;
            verification_key.key = ecdsa;
            certificate.subject_attributes.push_back(verification_key);
        },

        // For OQS
        [&](const generic_key::KeyPairOQS& subject_key) {
            oqs_nist oqs_key;
            oqs_key.type = subject_key.public_key.m_type;
            oqs_key.public_key.K = subject_key.public_key.pub_K;
            VerificationKey verification_key;
            verification_key.key = oqs_key;
            certificate.subject_attributes.push_back(verification_key);
        });

    if (m_hybrid) {
        outer_subject_key =
            load_private_key_from_file(outer_subject_key_path, "ecdsa256");
        boost::apply_visitor(visitor1, outer_subject_key);
    } else
        boost::apply_visitor(visitor1, subject_key);

    // section 6.7 in TS 103 097 v1.2.1
    // set validity restriction
    StartAndEndValidity start_and_end;
    start_and_end.start_validity = convert_time32(time_now - std::chrono::hours(1));
    start_and_end.end_validity = convert_time32(time_now + std::chrono::hours(24 * validity_days));
    certificate.validity_restriction.push_back(start_and_end);

    std::cout << "Signing certificate... ";

    sort(certificate);

    auto visitor2 = compose_security(
        // For ECDSA
        [&](const ecdsa256::KeyPair& key_pair) {
            auto data_buffer = convert_for_signing(certificate);
            certificate.signature =
                openssl_backend.sign_data(key_pair.private_key, data_buffer);
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

                // Resizing the extension inner signature, all bits to 0
                certificate.hybrid_signature_extension.hybrid_sig.S.resize(
                    sig_size);
                memset(
                    certificate.hybrid_signature_extension.hybrid_sig.S.data(),
                    0, sig_size);

                auto data_buffer =
                    convert_for_signing(certificate);

                // Hybrid: Signing including zeroed extension using OQS
                Signature tmp = openssl_backend.sign_data(key_pair.private_key,
                                                          data_buffer);

                certificate.hybrid_signature_extension.hybrid_sig =
                    boost::get<OqsSignature>(tmp);

                // Hybrid: Signing including extension using ECDSA
                auto outer_key_pair =
                    boost::get<ecdsa256::KeyPair>(outer_subject_key);
                auto outer_data_buffer =
                    convert_for_signing(certificate);
                certificate.signature = openssl_backend.sign_data(
                    outer_key_pair.private_key, outer_data_buffer);
            } else {
                auto data_buffer =
                    convert_for_signing(certificate);
                // OQS: Signing the all the fields
                certificate.signature = openssl_backend.sign_data(
                    key_pair.private_key, data_buffer);
            }
        });
    boost::apply_visitor(visitor2, subject_key);

    std::cout << "OK" << std::endl;

    std::cout << "Writing certificate to '" << output << "'... ";
    save_certificate_to_file(output, certificate);
    std::cout << "OK" << std::endl;

   

    return 0;
}
