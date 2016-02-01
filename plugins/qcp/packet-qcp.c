/* qcp.c
 * Routines for Ethereal QCP dissection
 * Designed and engineered by Quantel Ltd.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void proto_register_qcp();
void proto_reg_handoff_qcp();
void dissect_qcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Initialize the protocol and registered fields */
static int proto_qcp          = -1;
static gint ett_qcp           = -1;
static int hf_qcp_type        = -1;
static int hf_qcp_stream      = -1;
static int hf_qcp_session     = -1;
static int hf_qcp_chunk       = -1;
static int hf_qcp_fraglen     = -1;
static int hf_qcp_fragoffset  = -1;
static int hf_qcp_comchunk    = -1;
static int hf_qcp_comoffset   = -1;
static int hf_qcp_winchunk    = -1;
static int hf_qcp_winoffset   = -1;
static int hf_qcp_startchunk  = -1;
static int hf_qcp_startoffset = -1;
static int hf_qcp_endchunk    = -1;
static int hf_qcp_endoffset   = -1;

static int global_qcp_port = 2530;

/* qcp definitions*/
enum { eUnknown, eData, eWindow, eResend, eNoData };

/* Register the protocol with Ethereal */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/
void proto_register_qcp(void)
{
  /* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] =
  {
    { &hf_qcp_type,       { "Type",            "qcp.type",           FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_qcp_stream,     { "Stream",          "qcp.stream",         FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_qcp_session,    { "Session",         "qcp.session",        FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_qcp_chunk,      { "Chunk",           "qcp.chunk",          FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_qcp_fraglen,    { "Frag Len",        "qcp.fraglen",        FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_qcp_fragoffset, { "Frag Offset",     "qcp.fragoffset",     FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL } },
    { &hf_qcp_comchunk,   { "Complete Chunk",  "qcp.completechunk",  FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_qcp_comoffset,  { "Complete Offset", "qcp.completeoffset", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL } },
    { &hf_qcp_winchunk,   { "Window Chunk",    "qcp.windowchunk",    FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_qcp_winoffset,  { "Window Offset",   "qcp.windowoffset",   FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL } },
    { &hf_qcp_startchunk, { "Start Chunk",     "qcp.startchunk",     FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_qcp_startoffset,{ "Start Offset",    "qcp.startoffset",    FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL } },
    { &hf_qcp_endchunk,   { "End Chunk",       "qcp.endchunk",       FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_qcp_endoffset,  { "End Offset",      "qcp.endoffset",      FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL } },
  };

  /* Setup protocol subtree array */
  static gint *ett[] =
  {
    &ett_qcp,
  };

  /* Register the protocol name and description */
  proto_qcp = proto_register_protocol("Quantel QCP (Quantel Clipnet Protocol)", "QCP", "qcp");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_qcp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void proto_reg_handoff_qcp(void)
{
  dissector_handle_t qcp_handle;

  qcp_handle = create_dissector_handle(dissect_qcp, proto_qcp);
  dissector_add_uint("udp.port", global_qcp_port, qcp_handle);
}

/* Code to actually dissect the packets */
static void dissect_qcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *qcp_tree;
  guint32 qcp_type;
  guint32 qcp_stream;
  guint32 qcp_session;
  guint32 qcp_chunk;
  guint32 qcp_fraglen;
  guint32 qcp_fragoffset;
  guint32 qcp_comchunk;
  guint32 qcp_comoffset;
  guint32 qcp_winchunk;
  guint32 qcp_winoffset;
  guint32 qcp_startchunk;
  guint32 qcp_startoffset;
  guint32 qcp_endchunk;
  guint32 qcp_endoffset;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "QCP");

  qcp_type    = tvb_get_letohs(tvb, 0);
  qcp_stream  = tvb_get_letohs(tvb, 2);
  qcp_session = tvb_get_ntohl(tvb, 4);

  switch(qcp_type)
  {
    case eData:
      qcp_chunk      = tvb_get_ntohl(tvb, 8);
      qcp_fraglen    = tvb_get_ntohl(tvb, 12);
      qcp_fragoffset = tvb_get_ntohl(tvb, 16);

      col_add_fstr (pinfo->cinfo, COL_INFO, "Data (Session %d:%d Chunk %d,0x%08x Len %d)",
                    qcp_session, qcp_stream, qcp_chunk, qcp_fragoffset, qcp_fraglen);

      if(tree)
      {
        ti = proto_tree_add_item(tree, proto_qcp, tvb, 0, 24, FALSE);
        qcp_tree = proto_item_add_subtree(ti, ett_qcp);
        proto_tree_add_uint_format(qcp_tree, hf_qcp_type, tvb, 0, 2, qcp_type, "Type: %u (Data)", qcp_type);
        proto_tree_add_item(qcp_tree, hf_qcp_stream, tvb, 2, 2, FALSE);
        proto_tree_add_item(qcp_tree, hf_qcp_session, tvb, 4, 4, FALSE);
        proto_tree_add_item(qcp_tree, hf_qcp_chunk, tvb, 8, 4, FALSE);
        proto_tree_add_item(qcp_tree, hf_qcp_fraglen, tvb, 12, 4, FALSE);
        proto_tree_add_item(qcp_tree, hf_qcp_fragoffset, tvb, 16, 4, FALSE);
      }

      break;

    case eWindow:
      qcp_comchunk  = tvb_get_ntohl(tvb, 8);
      qcp_comoffset = tvb_get_ntohl(tvb, 12);
      qcp_winchunk  = tvb_get_ntohl(tvb, 16);
      qcp_winoffset = tvb_get_ntohl(tvb, 20);

      col_add_fstr (pinfo->cinfo, COL_INFO,
                    "Window (Session %d:%d Complete %d,0x%08x Window %d,0x%08x)",
                    qcp_session, qcp_stream, qcp_comchunk, qcp_comoffset, qcp_winchunk, qcp_winoffset);

      if(tree)
      {
        ti = proto_tree_add_item(tree, proto_qcp, tvb, 0, 24, FALSE);
        qcp_tree = proto_item_add_subtree(ti, ett_qcp);
        proto_tree_add_uint_format(qcp_tree, hf_qcp_type, tvb, 0, 2, qcp_type, "Type: %u (Window)", qcp_type);
        proto_tree_add_item(qcp_tree, hf_qcp_stream, tvb, 2, 2, FALSE);
        proto_tree_add_item(qcp_tree, hf_qcp_session, tvb, 4, 4, FALSE);
        proto_tree_add_item(qcp_tree, hf_qcp_comchunk, tvb, 8, 4, FALSE);
        proto_tree_add_item(qcp_tree, hf_qcp_comoffset, tvb, 12, 4, FALSE);
        proto_tree_add_item(qcp_tree, hf_qcp_winchunk, tvb, 16, 4, FALSE);
        proto_tree_add_item(qcp_tree, hf_qcp_winoffset, tvb, 20, 4, FALSE);
      }

      break;

    case eResend:
      qcp_startchunk  = tvb_get_ntohl(tvb, 8);
      qcp_startoffset = tvb_get_ntohl(tvb, 12);
      qcp_endchunk    = tvb_get_ntohl(tvb, 16);
      qcp_endoffset   = tvb_get_ntohl(tvb, 20);

      col_add_fstr (pinfo->cinfo, COL_INFO,
                    "Resend (Session %d:%d Start %d,0x%08x End %d,0x%08x)",
                    qcp_session, qcp_stream, qcp_startchunk, qcp_startoffset, qcp_endchunk, qcp_endoffset);

      if(tree)
      {
        ti = proto_tree_add_item(tree, proto_qcp, tvb, 0, 24, FALSE);
        qcp_tree = proto_item_add_subtree(ti, ett_qcp);
        proto_tree_add_uint_format(qcp_tree, hf_qcp_type, tvb, 0, 2, qcp_type, "Type: %u (Resend)", qcp_type);
        proto_tree_add_item(qcp_tree, hf_qcp_stream, tvb, 2, 2, FALSE);
        proto_tree_add_item(qcp_tree, hf_qcp_session, tvb, 4, 4, FALSE);
        proto_tree_add_item(qcp_tree, hf_qcp_startchunk, tvb, 8, 4, FALSE);
        proto_tree_add_item(qcp_tree, hf_qcp_startoffset, tvb, 12, 4, FALSE);
        proto_tree_add_item(qcp_tree, hf_qcp_endchunk, tvb, 16, 4, FALSE);
        proto_tree_add_item(qcp_tree, hf_qcp_endoffset, tvb, 20, 4, FALSE);
      }

      break;

    case eNoData:
      qcp_startchunk  = tvb_get_ntohl(tvb, 8);
      qcp_startoffset = tvb_get_ntohl(tvb, 12);
      qcp_endchunk    = tvb_get_ntohl(tvb, 16);
      qcp_endoffset   = tvb_get_ntohl(tvb, 20);

      col_add_fstr (pinfo->cinfo, COL_INFO,
                    "NoData (Session %d:%d Start %d,0x%08x End %d,0x%08x)",
                    qcp_session, qcp_stream, qcp_startchunk, qcp_startoffset, qcp_endchunk, qcp_endoffset);

      if(tree)
      {
        ti = proto_tree_add_item(tree, proto_qcp, tvb, 0, 24, FALSE);
        qcp_tree = proto_item_add_subtree(ti, ett_qcp);
        proto_tree_add_uint_format(qcp_tree, hf_qcp_type, tvb, 0, 2, qcp_type, "Type: %u (NoData)", qcp_type);
        proto_tree_add_item(qcp_tree, hf_qcp_stream, tvb, 2, 2, FALSE);
        proto_tree_add_item(qcp_tree, hf_qcp_session, tvb, 4, 4, FALSE);
        proto_tree_add_item(qcp_tree, hf_qcp_startchunk, tvb, 8, 4, FALSE);
        proto_tree_add_item(qcp_tree, hf_qcp_startoffset, tvb, 12, 4, FALSE);
        proto_tree_add_item(qcp_tree, hf_qcp_endchunk, tvb, 16, 4, FALSE);
        proto_tree_add_item(qcp_tree, hf_qcp_endoffset, tvb, 20, 4, FALSE);
      }

      break;

    default:
      col_add_fstr (pinfo->cinfo, COL_INFO, "QCP Unknown Type %d", qcp_type);
      break;
  }
}

