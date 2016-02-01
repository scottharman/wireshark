/* cqp.c
 * Routines for Ethereal CQP dissection
 * Designed and engineered by Quantel Ltd.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void proto_register_cqp();
void proto_reg_handoff_cqp();
void dissect_cqp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Initialize the protocol and registered fields */
static int proto_cqp             = -1;
static gint ett_cqp              = -1;
static int hf_cqp_magic          = -1;
static int hf_cqp_code           = -1;
static int hf_cqp_length         = -1;
static int hf_cqp_session        = -1;
static int hf_cqp_clientip       = -1;
static int hf_cqp_clientport     = -1;
static int hf_cqp_maxpacket      = -1;
static int hf_cqp_maxwindow      = -1;
static int hf_cqp_chunkbytes     = -1;
static int hf_cqp_chunkunit      = -1;
static int hf_cqp_poolid         = -1;
static int hf_cqp_startthunk     = -1;
static int hf_cqp_startatomms    = -1;
static int hf_cqp_startatomls    = -1;
static int hf_cqp_startskew      = -1;
static int hf_cqp_numthunks      = -1;
static int hf_cqp_numatoms       = -1;
static int hf_cqp_rushidms       = -1;
static int hf_cqp_rushidls       = -1;
static int hf_cqp_rushidfirstms  = -1;
static int hf_cqp_rushidfirstls  = -1;
static int hf_cqp_rushidsecondms = -1;
static int hf_cqp_rushidsecondls = -1;
static int hf_cqp_rushframe      = -1;
static int hf_cqp_formatcode     = -1;
static int hf_cqp_ticket         = -1;
static int hf_cqp_priority       = -1;

static int global_cqp_port = 2531;

enum { eUnknown, eSRECEIVE, eSSEND, eCACCEPT, eGETFRAG, eFRAGREPLY, eCREJECT,
       eSPOST, eSRECEIVEV3, eSSENDV3, eCACCEPTV3 };

const guint32 kMagic = 0x514e4554;

/* Register the protocol with Ethereal */

/* this format is required because a script is used to build the C function
   that calls all the protocol registration.
*/
void proto_register_cqp(void)
{
  /* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    { &hf_cqp_magic,          { "Magic",             "cqp.magic",          FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL } },
    { &hf_cqp_code,           { "Code",              "cqp.code",           FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_cqp_length,         { "Length",            "cqp.length",         FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_cqp_session,        { "Session",           "cqp.session",        FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_cqp_clientip,       { "Client IP",         "cqp.clientip",       FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL } },
    { &hf_cqp_clientport,     { "Client Port",       "cqp.clientport",     FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_cqp_maxpacket,      { "Max Packet",        "cqp.maxpacket",      FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_cqp_maxwindow,      { "Max Window",        "cqp.maxwindow",      FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_cqp_chunkbytes,     { "Chunk Bytes",       "cqp.chunkbytes",     FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL } },
    { &hf_cqp_chunkunit,      { "Chunk Unit",        "cqp.chunkunit",      FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_cqp_poolid,         { "Pool Id",           "cqp.poolid",         FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_cqp_startthunk,     { "Start Thunk",       "cqp.startthunk",     FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL } },
    { &hf_cqp_startatomms,    { "Start Atom MS",     "cqp.startatomms",    FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL } },
    { &hf_cqp_startatomls,    { "Start Atom LS",     "cqp.startatomls",    FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL } },
    { &hf_cqp_startskew,      { "Start Skew",        "cqp.startskew",      FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_cqp_numthunks,      { "Num Thunks",        "cqp.numthunks",      FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_cqp_numatoms,       { "Num Atoms",         "cqp.numatoms",       FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_cqp_rushidms,       { "Rush Id MS",        "cqp.rushidms",       FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL } },
    { &hf_cqp_rushidls,       { "Rush Id LS",        "cqp.rushidls",       FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL } },
    { &hf_cqp_rushidfirstms,  { "Rush Id First MS",  "cqp.rushidfirstms",  FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL } },
    { &hf_cqp_rushidfirstls,  { "Rush Id First LS",  "cqp.rushidfirstls",  FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL } },
    { &hf_cqp_rushidsecondms, { "Rush Id Second MS", "cqp.rushidsecondms", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL } },
    { &hf_cqp_rushidsecondls, { "Rush Id Second LS", "cqp.rushidsecondls", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL } },
    { &hf_cqp_rushframe,      { "Rush Frame",        "cqp.rushframe",      FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_cqp_formatcode,     { "Format Code",       "cqp.formatcode",     FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_cqp_ticket,         { "Ticket",            "cqp.ticket",         FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_cqp_priority,       { "Priority",          "cqp.priority",       FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
  };

  /* Setup protocol subtree array */
  static gint *ett[] =
  {
    &ett_cqp,
  };

  /* Register the protocol name and description */
  proto_cqp = proto_register_protocol("Quantel CQP (Clipnet Quentin Protocol)", "CQP", "cqp");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_cqp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void proto_reg_handoff_cqp(void)
{
  dissector_handle_t cqp_handle;

  cqp_handle = create_dissector_handle(dissect_cqp, proto_cqp);
  dissector_add_uint("tcp.port", global_cqp_port, cqp_handle);
}

void dissect_v2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, char *summary, char *type, char *magicstr)
{
  /* Helper function which dissects V2 style packets */

  proto_item *ti;
  proto_tree *cqp_tree;
  guint32 magic;
  guint32 code;
  guint32 session;
  guint32 numthunks;
  guint32 rushidms;
  guint32 rushidls;
  guint32 rushframe;
  guint32 formatcode;

  magic       = tvb_get_ntohl(tvb, 0);
  code        = tvb_get_ntohl(tvb, 4);
  session     = tvb_get_ntohl(tvb, 12);
  numthunks   = tvb_get_ntohl(tvb, 48);
  rushidms    = tvb_get_ntohl(tvb, 52);
  rushidls    = tvb_get_ntohl(tvb, 56);
  rushframe   = tvb_get_ntohl(tvb, 60);
  formatcode  = tvb_get_ntohl(tvb, 64);

  sprintf(summary, "%s (Session %d RushId %08x-%08x RushFrame %d Atoms %d Format %d)", type, session, rushidms, rushidls, rushframe, numthunks, formatcode);

  if(tree)
  {
     ti = proto_tree_add_item(tree, proto_cqp, tvb, 0, 76, FALSE);
     cqp_tree = proto_item_add_subtree(ti, ett_cqp);

     proto_tree_add_uint_format(cqp_tree, hf_cqp_magic, tvb, 0, 4, magic, "Magic: %08x (%s)", magic, magicstr);
     proto_tree_add_uint_format(cqp_tree, hf_cqp_code, tvb, 4, 4, code, "Type: %u (%s)", code, type);
     proto_tree_add_item(cqp_tree, hf_cqp_length, tvb, 8, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_session, tvb, 12, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_clientip, tvb, 16, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_clientport, tvb, 20, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_maxpacket, tvb, 24, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_maxwindow, tvb, 28, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_chunkbytes, tvb, 32, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_chunkunit, tvb, 36, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_poolid, tvb, 40, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_startthunk, tvb, 44, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_numthunks, tvb, 48, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_rushidms, tvb, 52, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_rushidls, tvb, 56, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_rushframe, tvb, 60, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_formatcode, tvb, 64, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_ticket, tvb, 68, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_priority, tvb, 72, 4, FALSE);
  }
}

void dissect_v3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, char *summary, char *type, char *magicstr)
{
  /* Helper function which dissects V3 style packets */

  proto_item *ti;
  proto_tree *cqp_tree;
  guint32 magic;
  guint32 code;
  guint32 session;
  guint32 numatoms;
  guint32 rushidsecondms;
  guint32 rushidsecondls;
  guint32 rushframe;
  guint32 formatcode;

  magic          = tvb_get_ntohl(tvb, 0);
  code           = tvb_get_ntohl(tvb, 4);
  session        = tvb_get_ntohl(tvb, 12);
  numatoms       = tvb_get_ntohl(tvb, 56);
  rushidsecondms = tvb_get_ntohl(tvb, 68);
  rushidsecondls = tvb_get_ntohl(tvb, 72);
  rushframe      = tvb_get_ntohl(tvb, 76);
  formatcode     = tvb_get_ntohl(tvb, 80);

  sprintf(summary, "%s (Session %d RushId %08x-%08x RushFrame %d Atoms %d Format %d)", type, session, rushidsecondms, rushidsecondls, rushframe, numatoms, formatcode);

  if(tree)
  {
     ti = proto_tree_add_item(tree, proto_cqp, tvb, 0, 92, FALSE);
     cqp_tree = proto_item_add_subtree(ti, ett_cqp);

     proto_tree_add_uint_format(cqp_tree, hf_cqp_magic, tvb, 0, 4, magic, "Magic: %08x (%s)", magic, magicstr);
     proto_tree_add_uint_format(cqp_tree, hf_cqp_code, tvb, 4, 4, code, "Type: %u (%s)", code, type);
     proto_tree_add_item(cqp_tree, hf_cqp_length, tvb, 8, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_session, tvb, 12, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_clientip, tvb, 16, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_clientport, tvb, 20, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_maxpacket, tvb, 24, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_maxwindow, tvb, 28, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_chunkbytes, tvb, 32, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_chunkunit, tvb, 36, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_poolid, tvb, 40, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_startatomms, tvb, 44, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_startatomls, tvb, 48, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_startskew, tvb, 52, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_numatoms, tvb, 56, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_rushidfirstms, tvb, 60, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_rushidfirstls, tvb, 64, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_rushidsecondms, tvb, 68, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_rushidsecondls, tvb, 72, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_rushframe, tvb, 76, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_formatcode, tvb, 80, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_ticket, tvb, 84, 4, FALSE);
     proto_tree_add_item(cqp_tree, hf_cqp_priority, tvb, 88, 4, FALSE);
  }
}

/* Code to actually dissect the packets */
static void dissect_cqp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint32 magic;
  guint32 code;
  guint32 length;
  guint32 reason;
  char summary[128];
  char magicstr[128];

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "CQP");

  magic  = tvb_get_ntohl(tvb, 0);
  code   = tvb_get_ntohl(tvb, 4);
  length = tvb_get_ntohl(tvb, 8);

  if(magic == kMagic) sprintf(magicstr, "Correct");
  else sprintf(magicstr, "Incorrect - should be %08x", kMagic);

  switch(code)
  {
    case eSRECEIVE:
      dissect_v2(tvb, pinfo, tree, summary, "SReceive", magicstr);
      break;
    case eSSEND:
      dissect_v2(tvb, pinfo, tree, summary, "SSend", magicstr);
      break;
    case eCACCEPT:
      dissect_v2(tvb, pinfo, tree, summary, "CAccept", magicstr);
      break;
    case eGETFRAG:
      sprintf(summary, "GetFrag");
      break;
    case eFRAGREPLY:
      sprintf(summary, "FragReply");
      break;
    case eCREJECT:
      reason = tvb_get_ntohl(tvb, 16);
      sprintf(summary, "CReject, Reason %d", reason);
      break;
    case eSPOST:
      sprintf(summary, "SPost");
      break;
    case eSRECEIVEV3:
      dissect_v3(tvb, pinfo, tree, summary, "SReceiveV3", magicstr);
      break;
    case eSSENDV3:
      dissect_v3(tvb, pinfo, tree, summary, "SSendV3", magicstr);
      break;
    case eCACCEPTV3:
      dissect_v3(tvb, pinfo, tree, summary, "CAcceptV3", magicstr);
      break;
    default:
      sprintf(summary, "Unknown Type %d",code);
      break;
  }

  col_add_str(pinfo->cinfo, COL_INFO, summary);
}

