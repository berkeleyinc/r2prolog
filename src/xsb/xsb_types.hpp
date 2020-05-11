// Copyright 2016-2018 Carnegie Mellon University.  See LICENSE file for terms.

// Author: Michael Duggan

#ifndef Pharos_XSB_TYPES_HPP
#define Pharos_XSB_TYPES_HPP

#include <cstdint>

namespace pharos { namespace prolog { namespace impl { inline namespace xsb {

// This validity of these types are asserted in xsb.cpp.
using xsb_int = std::int64_t; //@XSB_PINT_TYPE@ ;
using xsb_term = std::uint64_t; //@XSB_PTERM_TYPE@ ;

}}}}

#endif

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
