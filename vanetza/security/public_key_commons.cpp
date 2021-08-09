#include <cassert>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/public_key_commons.hpp>
namespace vanetza {
namespace security {
void serialize(OutputArchive& ar, const OqsPublicKey& key,
               PublicKeyAlgorithm algo) {
    assert(key.K.size() == field_size(algo));
    for (auto& byte : key.K) {
        ar << byte;
    }
}

void deserialize(InputArchive& ar, OqsPublicKey& key, PublicKeyAlgorithm algo) {
    size_t size = field_size(algo);
    uint8_t elem;
    for (size_t c = 0; c < size; c++) {
        ar >> elem;
        key.K.push_back(elem);
    }
}

size_t get_size(const OqsPublicKey& key) { return key.K.size(); }

}  // namespace security
}  // namespace vanetza