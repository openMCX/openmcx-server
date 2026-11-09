//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Canonical XML 1.1 (W3C Recommendation 2 May 2008) of a document subset, with the processing of the attributes in
// the XML namespace of its clause 2.4 (xml:lang and xml:space inherited, xml:id not, xml:base fixed up with
// join-URI-References, other xml: attributes ordinary). libxml2's own Canonical XML 1.1 mode differs from that
// clause (a trailing "..", fragments, dot segments of an absolute value, an element's own empty xml:base); its
// attribute axis is the only place where its Canonical XML 1.0 and 1.1 modes differ, so the canonical form here is
// libxml2's Canonical XML 1.0 one over the document with its xml: attributes prepared for the duration of the call.

#pragma once

#include <libxml/c14n.h>
#include <libxml/tree.h>

namespace mcx::xmlsec {

//------------------------------------------------------------------------------
// xmlC14NExecute with the Canonical XML 1.1 mode, as above: the same arguments and result; the document is unchanged
// on return. Throws for a node-set where an element whose parent is omitted has a visible ancestor beyond with an
// xml: attribute other than xml:lang and xml:space (also its xml:base, own or fixed up) that the element does not
// have itself in the node-set, or where a fixed-up xml:base would be outside the node-set (none of the node-sets of
// the XML signatures here: a subtree less subtrees).
int c14n11_execute(xmlDocPtr doc, xmlC14NIsVisibleCallback is_visible, void *user_data, int with_comments,
                   xmlOutputBufferPtr buffer);

} // namespace mcx::xmlsec
