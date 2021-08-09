#ifndef CERTIFY_COMMANDS_GENERATE_KEY_HPP
#define CERTIFY_COMMANDS_GENERATE_KEY_HPP

#include "command.hpp"

class GenerateKeyCommand : public Command
{
public:
    GenerateKeyCommand(const std::string&);
    bool parse(const std::vector<std::string>&) override;
    int execute() override;

private:
    std::string output;
    std::string m_signature_key_type;
};

#endif /* CERTIFY_COMMANDS_GENERATE_KEY_HPP */
