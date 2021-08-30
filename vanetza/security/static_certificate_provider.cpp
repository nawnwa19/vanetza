#include <vanetza/security/static_certificate_provider.hpp>

namespace vanetza
{
namespace security
{

StaticCertificateProvider::StaticCertificateProvider(const Certificate& authorization_ticket,
        const generic_key::PrivateKey& authorization_ticket_key) :
    StaticCertificateProvider(authorization_ticket, authorization_ticket_key, std::list<Certificate> {})
{
}

StaticCertificateProvider::StaticCertificateProvider(const Certificate& authorization_ticket,
        const generic_key::PrivateKey& authorization_ticket_key, const std::list<Certificate>& chain) :
    authorization_ticket(authorization_ticket), authorization_ticket_key(authorization_ticket_key), chain(chain)
{
}

StaticCertificateProvider::StaticCertificateProvider(
    const Certificate& authorization_ticket,
    const generic_key::PrivateKey& authorization_ticket_key,
    const generic_key::PrivateKey& at_outer_key,
    const std::list<Certificate>& chain, bool hybrid)
    : authorization_ticket(authorization_ticket),
      authorization_ticket_key(authorization_ticket_key),
      authorization_ticket_outer_key(at_outer_key),
      chain(chain),
      m_hybrid(hybrid) {}

const generic_key::PrivateKey& StaticCertificateProvider::own_private_key()
{
    if (m_hybrid)
        return own_private_outer_key();
    else
        return authorization_ticket_key;
}

const generic_key::PrivateKey& StaticCertificateProvider::own_private_outer_key()
{
    return authorization_ticket_outer_key;
}

std::list<Certificate> StaticCertificateProvider::own_chain()
{
    return chain;
}

const Certificate& StaticCertificateProvider::own_certificate()
{
    return authorization_ticket;
}

} // namespace security
} // namespace vanetza
