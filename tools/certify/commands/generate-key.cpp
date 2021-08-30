#include "generate-key.hpp"
#include <boost/program_options.hpp>
#include <cryptopp/eccrypto.h>
#include <cryptopp/files.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <cryptopp/queue.h>
#include <cryptopp/sha.h>
#include <iostream>
#include <stdexcept>
#include <vanetza/security/public_key.hpp>
#include <fstream>
#include <vanetza/security/generic_key.hpp>
#include <vanetza/common/archives.hpp>

namespace po = boost::program_options;
using namespace CryptoPP;
GenerateKeyCommand::GenerateKeyCommand(const std::string& sig_key_type)
    : m_signature_key_type(sig_key_type) {}

bool GenerateKeyCommand::parse(const std::vector<std::string>& opts)
{
    po::options_description desc("Available options");
    desc.add_options()
        ("help", "Print out available options.")
        ("output", po::value<std::string>(&output)->required(), "Output file.")
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

int GenerateKeyCommand::execute()
{
    int result = 0;
    std::cout << "Generating " << m_signature_key_type << " key..." << std::endl;
    namespace vs = vanetza::security;
    vs::PublicKeyAlgorithm type = vs::get_algo_from_string(m_signature_key_type);
    switch (type) {
        case vs::PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256:{
            AutoSeededRandomPool rng;
            OID oid(CryptoPP::ASN1::secp256r1());
            ECDSA<ECP, SHA256>::PrivateKey private_key;
            private_key.Initialize(rng, oid);

            if (!private_key.Validate(rng, 3)) {
                throw std::runtime_error("Private key validation failed");
            }

            ByteQueue queue;
            private_key.Save(queue);
            CryptoPP::FileSink file(output.c_str());
            queue.CopyTo(file);
            file.MessageEnd();
            break;
        }
        case vs::PublicKeyAlgorithm::ECIES_NISTP256:
        case vs::PublicKeyAlgorithm::UNKNOWN:
            result = -1;
            break;
        default: { // For all OQS types
            vs::generic_key::KeyPairOQS kp;
            kp.private_key.m_type = vs::get_algo_from_string(m_signature_key_type);
            kp.public_key.m_type = kp.private_key.m_type;
            
            oqs::Signature signer{m_signature_key_type};
            kp.public_key.pub_K = signer.generate_keypair();
            kp.private_key.priv_K = signer.export_secret_key();

            // Store the exported private key into a file
            std::ofstream fout(output, std::ios::binary);
            vanetza::OutputArchive ar(fout);
            try
            {
                vs::generic_key::serialize(ar,kp,type);
            }
            catch(const std::exception& e)
            {
                std::cerr << e.what() << '\n';
            }
            break;
        } 
    }
    return result;
}
