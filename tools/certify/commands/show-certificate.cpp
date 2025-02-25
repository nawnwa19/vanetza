#include "show-certificate.hpp"
#include <boost/algorithm/hex.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/program_options.hpp>
#include <boost/variant.hpp>
#include <fstream>
#include <iostream>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/cam_ssp.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/persistence.hpp>

namespace po = boost::program_options;
using namespace vanetza;
using namespace vanetza::security;

bool ShowCertificateCommand::parse(const std::vector<std::string>& opts)
{
    po::options_description desc("Available options");
    desc.add_options()
        ("help", "Print out available options.")
        ("certificate", po::value<std::string>(&certificate_path)->required(), "Certificate to show.")
    ;

    po::positional_options_description pos;
    pos.add("certificate", 1);

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

int ShowCertificateCommand::execute()
{
    Certificate cert = load_certificate_from_file(certificate_path);
    std::cout << "Version: " << cert.version;
    // subject info

    std::cout << "Subject: ";

    if (cert.subject_info.subject_type == SubjectType::Enrollment_Credential) {
        std::cout << "Enrollment Credential";
    } else if (cert.subject_info.subject_type == SubjectType::Authorization_Ticket) {
        std::cout << "Authorization Ticket";
    } else if (cert.subject_info.subject_type == SubjectType::Authorization_Authority) {
        std::cout << "Authorization Authority";
    } else if (cert.subject_info.subject_type == SubjectType::Enrollment_Authority) {
        std::cout << "Enrollment Authority";
    } else if (cert.subject_info.subject_type == SubjectType::Root_CA) {
        std::cout << "Root Authority";
    } else if (cert.subject_info.subject_type == SubjectType::CRL_Signer) {
        std::cout << "CRL Signer";
    }

    if (cert.subject_info.subject_name.size() > 0) {
        std::string subject_name(reinterpret_cast<const char*>(&cert.subject_info.subject_name[0]), cert.subject_info.subject_name.size());
        std::cout << " (" << subject_name << ")";
    }

    std::cout << std::endl;

    {
        HashedId8 cert_id = calculate_hash(cert);
        std::string cert_id_string(reinterpret_cast<const char*>(&cert_id[0]), cert_id.size());
        std::cout << "Digest: " << boost::algorithm::hex(cert_id_string) << " (SHA-256)" << std::endl;
    }

    // signer info

    std::cout << "Signer: ";

    SignerInfoType signer_type = get_type(cert.signer_info);

    if (signer_type == SignerInfoType::Self) {
        std::cout << "Self-Signed";
    } else if (signer_type == SignerInfoType::Certificate_Digest_With_SHA256) {
        HashedId8 signer = boost::get<HashedId8>(cert.signer_info);
        std::string signer_id(reinterpret_cast<const char*>(&signer[0]), signer.size());
        std::cout << boost::algorithm::hex(signer_id) << " (SHA-256)";
    } else {
        std::cout << "Unknown (" << static_cast<int>(signer_type) << ")";
    }

    std::cout << std::endl;

    // subject attributes

    std::cout << std::endl;

    // TODO Support Verification_Key, Encryption_Key, Reconstruction_Value

    unsigned certificate_application_ids = 0;

    for (auto& subject_attr : cert.subject_attributes) {
        SubjectAttributeType attr_type = get_type(subject_attr);
        if (attr_type == SubjectAttributeType::Assurance_Level) {
            SubjectAssurance assurance = boost::get<SubjectAssurance>(subject_attr);
            std::cout << "Assurance: " << (assurance.raw & assurance.assurance_mask);
            std::cout << " with a confidence of " <<  (assurance.raw & assurance.confidence_mask);
            std::cout << std::endl << std::endl;
        } else if (attr_type == SubjectAttributeType::ITS_AID_List) {
            std::list<IntX> its_application_ids = boost::get<std::list<IntX>>(subject_attr);

            std::cout << "ITS Application IDs:" << std::endl;
            if (its_application_ids.size() == 0) {
                std::cout << "None";
            } else {
                for (auto& its_application_id : its_application_ids) {
                    certificate_application_ids++;

                    std::cout << " - ";
                    if (its_application_id == aid::CA) {
                        std::cout << "36 (CA-Basic service)";
                    } else if (its_application_id == aid::DEN) {
                        std::cout << "37 (DEN-Basic service)";
                    } else {
                        std::cout << its_application_id.get();
                    }
                    std::cout << std::endl;
                }
            }
            std::cout << std::endl;
        } else if (attr_type == SubjectAttributeType::ITS_AID_SSP_List) {
            std::list<ItsAidSsp> its_service_specific_permissions = boost::get<std::list<ItsAidSsp>>(subject_attr);
            for (auto& its_ssp : its_service_specific_permissions) {
                if (its_ssp.its_aid == aid::CA) {
                    std::cout << "CA - ITS Service Specific Permissions:" << std::endl;
                    ByteBuffer& ssp = its_ssp.service_specific_permissions;

                    if (ssp.size() == 0) {
                        std::cerr << "Invalid service specific permissions for CA" << std::endl;
                        continue;
                    }

                    // See final draft ETSI EN 302 637-2 V1.3.1 (2014-09)
                    if (ssp[0] == 0) {
                        if (ssp.size() != 1) {
                            std::cout << " - Warning: Length of SSP is expected to be 1, but was " << ssp.size() << std::endl;
                        } else {
                            std::cout << " - No version, shall be used only for testing." << std::endl;
                        }
                    } else if (ssp[0] == 1) {
                        if (ssp.size() != 3) {
                            std::cout << " - Warning: Length of SSP is expected to be 3, but was " << ssp.size() << std::endl;
                        } else {
                            CamPermissions ssp_decoded = CamPermissions::decode(ssp);
                            for (auto permission : ssp_decoded.permissions()) {
                                std::cout << " - " << stringify(permission) << "\n";
                            }
                        }
                    } else {
                        std::cout << " - Reserved for future usage and not implemented." << std::endl;
                    }

                    std::cout << std::endl;
                }
            }
        }
    }

    if (certificate_application_ids == 0) {
        std::cout << "Warning: Certificate doesn't contain any application IDs." << std::endl << std::endl;
    }

    // validity restrictions

    const boost::posix_time::ptime epoch {
        boost::gregorian::date(2004, 1, 1),
        boost::posix_time::milliseconds(0)
    };

    unsigned certificate_time_constraints = 0;

    for (auto& validity_restriction : cert.validity_restriction) {
        ValidityRestrictionType restriction_type = get_type(validity_restriction);
        if (restriction_type == ValidityRestrictionType::Time_End) {
            certificate_time_constraints++;

            boost::posix_time::ptime time_end = epoch + boost::posix_time::seconds(boost::get<EndValidity>(validity_restriction));
            std::cout << "Validity ends " << time_end << std::endl;
        } else if (restriction_type == ValidityRestrictionType::Time_Start_And_End) {
            certificate_time_constraints++;

            StartAndEndValidity start_and_end = boost::get<StartAndEndValidity>(validity_restriction);
            boost::posix_time::ptime time_start = epoch + boost::posix_time::seconds(start_and_end.start_validity);
            boost::posix_time::ptime time_end = epoch + boost::posix_time::seconds(start_and_end.end_validity);
            std::cout << "Validity starts " << time_start << " and ends " << time_end << std::endl;
        } else if (restriction_type == ValidityRestrictionType::Time_Start_And_Duration) {
            certificate_time_constraints++;

            StartAndDurationValidity start_and_duration = boost::get<StartAndDurationValidity>(validity_restriction);
            boost::posix_time::ptime time_start = epoch + boost::posix_time::seconds(start_and_duration.start_validity);
            boost::posix_time::ptime time_end = epoch + boost::posix_time::seconds(start_and_duration.duration.to_seconds().count());
            std::cout << "Validity starts " << time_start << " and ends " << time_end << std::endl;
        }
    }

    if (certificate_time_constraints == 0) {
        std::cout << "Warning: Certificate doesn't have any time based validity restriction." << std::endl;
    } else if (certificate_time_constraints > 1) {
        std::cout << "Warning: Certificate has multiple time based validity restrictions." << std::endl;
    }

    std::cout << std::endl;

    bool certificate_region_constraints = false;

    for (auto& validity_restriction : cert.validity_restriction) {
        ValidityRestrictionType restriction_type = get_type(validity_restriction);
        if (restriction_type == ValidityRestrictionType::Region) {
            certificate_region_constraints = true;

            GeographicRegion region = boost::get<GeographicRegion>(validity_restriction);

            std::cout << "This certificate is regionally restricted by ";

            RegionType region_type = get_type(region);
            if (region_type == RegionType::None) {
                std::cout << "nothing";
            } else if (region_type == RegionType::Circle) {
                std::cout << "a circle";
            } else if (region_type == RegionType::Rectangle) {
                std::cout << "a set of rectangles";
            } else if (region_type == RegionType::Polygon) {
                std::cout << "a polygon";
            } else if (region_type == RegionType::ID) {
                std::cout << "an identified region";
            }

            std::cout << "." << std::endl;
        }
    }

    if (!certificate_region_constraints) {
        std::cout << "This certificate doesn't have any regional restriction." << std::endl;
    }

    return 0;
}
