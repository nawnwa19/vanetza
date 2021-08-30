#include <vanetza/security/extension.hpp> 
#include <boost/optional/optional.hpp>

namespace vanetza
{
namespace security
{

size_t get_size(const Extension& ext) {
    size_t size = sizeof(ext.hybrid_sig.sig_type);
    size += get_size(ext.hybrid_sig);
    size += get_size(ext.hybrid_key);
    return size;
}

void serialize(OutputArchive& ar, const Extension& ext) {
    serialize(ar, ext.hybrid_sig.sig_type);
    serialize(ar, ext.hybrid_sig);
    serialize(ar, ext.hybrid_key, ext.hybrid_sig.sig_type);
}

size_t deserialize(InputArchive& ar, Extension& ext) {
    deserialize(ar, ext.hybrid_sig.sig_type);
    deserialize(ar, ext.hybrid_sig, ext.hybrid_sig.sig_type);
    deserialize(ar, ext.hybrid_key, ext.hybrid_sig.sig_type);
    return get_size(ext);
}

boost::optional<Extension> extract_extension(const Extension& ext){
    return boost::optional<Extension>(ext.hybrid_sig.S.size() != 0, ext);
}

} // ns security
} // ns vanetza
