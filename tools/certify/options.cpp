#include "commands/extract-public-key.hpp"
#include "commands/generate-aa.hpp"
#include "commands/generate-key.hpp"
#include "commands/generate-root.hpp"
#include "commands/generate-ticket.hpp"
#include "commands/show-certificate.hpp"
#include "options.hpp"
#include <boost/program_options.hpp>
#include <iostream>
#include <memory>

namespace po = boost::program_options;

std::unique_ptr<Command> parse_options(int argc, const char *argv[])
{
    po::options_description global("Global options");
    std::string signature_key_type;
    global.add_options()
        ("command", po::value<std::string>(), "Command to execute.")
        ("subargs", po::value<std::vector<std::string>>(), "Arguments for command.")
        ("algorithm", po::value<std::string>(&signature_key_type)->default_value("ecdsa256"), "ECDSA,Dilithium2/3/5,Falcon-512,Falcon-1024")
    ;

    po::positional_options_description pos;
    pos.add("command", 1);
    pos.add("subargs", -1);

    po::variables_map vm;

    po::parsed_options parsed = po::command_line_parser(argc, argv)
        .options(global)
        .positional(pos)
        .allow_unregistered()
        .run();

    po::store(parsed, vm);
    po::notify(vm);

    std::string available_commands = "Available commands: generate-key, extract-public-key, generate-root, generate-aa, generate-ticket, show-certificate";

    if (!vm.count("command")) {
        std::cerr << global << std::endl;
        std::cerr << available_commands << std::endl;

        return nullptr;
    }

    std::string cmd = vm["command"].as<std::string>();
    std::unique_ptr<Command> command;

    if (cmd == "--help") {
        std::cerr << global << std::endl;
        std::cerr << available_commands << std::endl;
    } else if (cmd == "extract-public-key") {
        command.reset(new ExtractPublicKeyCommand(signature_key_type));
    } else if (cmd == "generate-aa") {
        command.reset(new GenerateAaCommand(signature_key_type));
    } else if (cmd == "generate-key") {
        command.reset(new GenerateKeyCommand(signature_key_type));
    } else if (cmd == "generate-root") {
        command.reset(new GenerateRootCommand(signature_key_type));
    } else if (cmd == "generate-ticket") {
        command.reset(new GenerateTicketCommand(signature_key_type));
    } else if (cmd == "show-certificate") {
        command.reset(new ShowCertificateCommand());
    } else {
        // unrecognized command
        throw po::invalid_option_value(cmd);
    }

    std::vector<std::string> opts = po::collect_unrecognized(parsed.options, po::include_positional);
    if (!opts.empty()) {
        opts.erase(opts.begin());
    }

    if (!command->parse(opts)) {
        return nullptr;
    }

    return command;
}
