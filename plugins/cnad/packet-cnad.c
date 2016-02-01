/* cnad.c
 * Routines for Ethereal Clipnet AutoDiscovery dissection
 * Designed and engineered by Quantel Ltd.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void proto_register_cnad();
void proto_reg_handoff_cnad();
void dissect_cnad(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Initialize the protocol and registered fields */
static int proto_cnad    = -1;
static gint ett_cnad     = -1;
static int hf_cnad_magic = -1;
static int hf_cnad_type  = -1;
static int hf_cnad_len   = -1;

static int global_cnad_port = 2529;

const guint32 kMagic = 0x434e4144;

enum { eBroadcast, eAYTReply, eAYT, eEcho, eEchoReply };

/* Register the protocol with Ethereal */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/
void proto_register_cnad(void)
{
  /* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] =
  {
    { &hf_cnad_magic, { "Magic", "cnad.magic",  FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_cnad_type,  { "Type",  "cnad.type",   FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_cnad_len,   { "Length","cnad.length", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
  };

  /* Setup protocol subtree array */
  static gint *ett[] =
  {
    &ett_cnad,
  };

  /* Register the protocol name and description */
  proto_cnad = proto_register_protocol("Quantel Clipnet AutoDiscovery Protocol", "CNAD", "cnad");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_cnad, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void proto_reg_handoff_cnad(void)
{
  dissector_handle_t cnad_handle;

  cnad_handle = create_dissector_handle(dissect_cnad, proto_cnad);
  dissector_add_uint("udp.port", global_cnad_port, cnad_handle);
}

/* Code to actually dissect the packets */
static void dissect_cnad(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *cnad_tree;
  guint32 cnad_magic;
  guint32 cnad_type;
  guint32 cnad_len;
  char summary[128];
  char magicstr[128];
  char *type = "";

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "CNAD");

  cnad_magic = tvb_get_ntohl(tvb, 0);
  cnad_type  = tvb_get_ntohl(tvb, 4);
  cnad_len   = tvb_get_ntohl(tvb, 8);

  if(cnad_magic == kMagic) sprintf(magicstr, "Correct");
  else sprintf(magicstr, "Incorrect - should be %08x", kMagic);

  switch(cnad_type)
  {
    case eBroadcast:
      type = "Broadcast";
      sprintf(summary, "%s", type);
      break;
    case eAYTReply:
      type = "AYT Reply";
      sprintf(summary, "%s", type);
      break;
    case eAYT:
      type = "AYT Request";
      sprintf(summary, "%s", type);
      break;
    case eEcho:
      type = "Echo Request";
      sprintf(summary, "%s, length %d", type, cnad_len);
      break;
    case eEchoReply:
      type = "Echo Reply";
      sprintf(summary, "%s, length %d", type, cnad_len);
      break;
    default:
      type = "Unknown";
      sprintf(summary, "CNAD %s Type %d", type, cnad_type);
      break;
  }

  col_add_str (pinfo->cinfo, COL_INFO, summary);

  if(tree)
  {
     ti = proto_tree_add_item(tree, proto_cnad, tvb, 0, 12, FALSE);
     cnad_tree = proto_item_add_subtree(ti, ett_cnad);
     proto_tree_add_uint_format(cnad_tree, hf_cnad_magic, tvb, 0, 4, cnad_magic, "Magic: %08x (%s)", cnad_magic, magicstr);
     proto_tree_add_uint_format(cnad_tree, hf_cnad_type,  tvb, 4, 4, cnad_type, "Type: %u (%s)", cnad_type, type);
     proto_tree_add_item(cnad_tree, hf_cnad_len, tvb, 8, 4, FALSE);
  }
}

