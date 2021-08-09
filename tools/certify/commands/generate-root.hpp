#ifndef CERTIFY_COMMANDS_GENERATE_ROOT_HPP
#define CERTIFY_COMMANDS_GENERATE_ROOT_HPP

#include "command.hpp"

class GenerateRootCommand : public Command
{
public:
    GenerateRootCommand(const std::string&);
    bool parse(const std::vector<std::string>&) override;
    int execute() override;

private:
    std::string m_signature_key_type;
    std::string subject_key_path;
    std::string output;
    std::string subject_name;
    int validity_days;
    std::vector<unsigned> aids;
};

#endif /* CERTIFY_COMMANDS_GENERATE_ROOT_HPP */
