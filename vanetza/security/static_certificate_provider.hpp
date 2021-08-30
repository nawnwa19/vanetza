#ifndef STATIC_CERTIFICATE_PROVIDER_HPP_MTULFLKX
#define STATIC_CERTIFICATE_PROVIDER_HPP_MTULFLKX

#include <vanetza/security/certificate_provider.hpp>

namespace vanetza
{
namespace security
{

/**
 * \brief A simple certificate provider
 *
 * This certificate provider uses a static certificate and key pair that is pre-generated.
 */
class StaticCertificateProvider : public CertificateProvider
{
public:
    /**
     * Create static certificate provider with empty chain
     * \param authorization_ticket
     * \param ticket_key private key of given authorization ticket
     */
    StaticCertificateProvider(const Certificate& authorization_ticket, const generic_key::PrivateKey& ticket_key);

    /**
     * Create static certificate provider with given chain
     * \param authorization_ticket
     * \param ticket_key private key of given authorization ticket
     * \param chain own certificate chain
     */
    StaticCertificateProvider(const Certificate& authorization_ticket, const generic_key::PrivateKey& ticket_key,
            const std::list<Certificate>& chain);
    StaticCertificateProvider(const Certificate& authorization_ticket,
                              const generic_key::PrivateKey& ticket_key,
                              const generic_key::PrivateKey& ticket_outer_key,
                              const std::list<Certificate>& chain,
                              bool hybrid);

    /**
     * Get own certificate to use for signing
     * \return own certificate
     */
    virtual const Certificate& own_certificate() override;

    /**
     * Get own certificate chain, excluding the leaf certificate and root CA
     * \return own certificate chain
     */
    virtual std::list<Certificate> own_chain() override;

    /**
     * Get private key associated with own certificate
     * \return private key
     */
    virtual const generic_key::PrivateKey& own_private_key() override;

private:
    const generic_key::PrivateKey& own_private_outer_key();
    Certificate authorization_ticket;
    generic_key::PrivateKey authorization_ticket_key;
    generic_key::PrivateKey authorization_ticket_outer_key;
    std::list<Certificate> chain;
    bool m_hybrid;
};

} // namespace security
} // namespace vanetza

#endif /* STATIC_CERTIFICATE_PROVIDER_HPP_MTULFLKX */
