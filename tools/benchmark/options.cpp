#include "cases/security/signing.hpp"
#include "cases/security/validation.hpp"
#include "options.hpp"
#include <boost/program_options.hpp>
#include <iostream>
#include <memory>

namespace po = boost::program_options;

std::unique_ptr<Case> parse_options(int argc, const char *argv[])
{
    po::options_description global("Global options");
    std::string signature_key_type;
    std::string hybrid_string;
    global.add_options()
        ("case", po::value<std::string>(), "Case to execute.")
        ("subargs", po::value<std::vector<std::string>>(), "Arguments for case.")
        ("algorithm", po::value<std::string>(&signature_key_type)->default_value("ecdsa256"), "ecdsa256,Dilithium3/5,Falcon-512,Falcon-1024")
        ("hybrid", po::value<std::string>(&hybrid_string)->default_value("no"), "Hybrid Certificates: yes or no");
    
    po::positional_options_description pos;
    pos.add("case", 1);
    pos.add("subargs", -1);

    po::variables_map vm;

    po::parsed_options parsed = po::command_line_parser(argc, argv)
        .options(global)
        .positional(pos)
        .allow_unregistered()
        .run();

    po::store(parsed, vm);
    po::notify(vm);

    std::string available_commands = "Available cases: security-validation, security-signing";

    if (!vm.count("case")) {
        std::cerr << global << std::endl;
        std::cerr << available_commands << std::endl;

        return nullptr;
    }

    // Hybrid or normal certificates
    bool hybrid = (hybrid_string == "yes"? true : false);
    if (hybrid) {
        if (signature_key_type == "ecdsa256")
            throw std::runtime_error("Must specify PQ algorithm with hybrid");
    }

    std::string name = vm["case"].as<std::string>();
    std::unique_ptr<Case> instance;

    if (name == "--help") {
        std::cerr << global << std::endl;
        std::cerr << available_commands << std::endl;
    } else if (name == "security-signing") {
        instance.reset(new SecuritySigningCase(signature_key_type,hybrid));
    } else if (name == "security-validation") {
        instance.reset(new SecurityValidationCase(signature_key_type,hybrid));
    } else {
        throw std::runtime_error("Unknown benchmark case.");
    }

    std::vector<std::string> opts = po::collect_unrecognized(parsed.options, po::include_positional);
    if (!opts.empty()){
        opts.erase(opts.begin());
    }

    if (!instance->parse(opts)) {
        return nullptr;
    }

    return instance;
}
