#ifndef CERTIFY_COMMANDS_GENERATE_TICKET_HPP
#define CERTIFY_COMMANDS_GENERATE_TICKET_HPP

#include "command.hpp"

class GenerateTicketCommand : public Command
{
public:
    GenerateTicketCommand(const std::string&);
    bool parse(const std::vector<std::string>&) override;
    int execute() override;

private:
    std::string m_signature_key_type;
    std::string output;
    std::string sign_key_path;
    std::string sign_cert_path;
    std::string subject_key_path;
    int validity_days;
    std::string cam_permissions;
    std::string denm_permissions;
    bool permit_gn_mgmt = false;
};

#endif /* CERTIFY_COMMANDS_GENERATE_TICKET_HPP */
