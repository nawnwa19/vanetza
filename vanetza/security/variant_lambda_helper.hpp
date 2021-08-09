#ifndef VARIANT_LAMBDA_HELPER_IOXLJFVZ
#define VARIANT_LAMBDA_HELPER_IOXLJFVZ
#include <boost/variant.hpp>
#include <type_traits>

namespace vanetza
{
    namespace security
    {
            template <typename... Lambdas>
            struct lambda_visitor;

            template <typename Lambda1, typename... Lambdas>
            struct lambda_visitor<Lambda1, Lambdas...>
                : public lambda_visitor<Lambdas...>,
                  public Lambda1
            {

                using Lambda1::operator();
                using lambda_visitor<Lambdas...>::operator();

                lambda_visitor(Lambda1 l1, Lambdas... lambdas)
                    : Lambda1(l1), lambda_visitor<Lambdas...>(lambdas...) {}
            };

            template <typename Lambda1>
            struct lambda_visitor<Lambda1>
                : public Lambda1
            {

                using Lambda1::operator();

                lambda_visitor(Lambda1 l1)
                    : Lambda1(l1) {}
            };
            
        template <class... Fs>
        auto compose_security(Fs &&...fs)
        {
            using visitor_type = lambda_visitor<std::decay_t<Fs>...>;
            return visitor_type(std::forward<Fs>(fs)...);
        };

    } // namespace security

} // namespace vanetza


#endif /* VARIANT_LAMBDA_HELPER_IOXLJFVZ */