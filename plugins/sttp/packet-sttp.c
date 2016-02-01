/* sttp.c
 * Routines for Ethereal CQP dissection
 * Designed and engineered by Quantel Ltd.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void proto_register_sttp();
void proto_reg_handoff_sttp();
void dissect_sttp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Initialize the protocol and registered fields */
static int proto_sttp     = -1;
static gint ett_sttp      = -1;
static int hf_sttp_pool   = -1;
static int hf_sttp_thunk  = -1;
static int hf_sttp_offset = -1;
static int hf_sttp_len    = -1;

static int global_sttp_port = 2550;

/* Register the protocol with Ethereal */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/
void proto_register_sttp(void)
{
  /* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] =
  {
    { &hf_sttp_pool,   { "Pool",   "sttp.pool",   FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_sttp_thunk,  { "Atom",   "sttp.atom",   FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_sttp_offset, { "Offset", "sttp.offset", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_sttp_len,    { "Length", "sttp.length", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
  };

  /* Setup protocol subtree array */
  static gint *ett[] =
  {
    &ett_sttp,
  };

  /* Register the protocol name and description */
  proto_sttp = proto_register_protocol("Quantel STTP (Sub-Thunk Transfer Protocol)", "STTP", "sttp");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_sttp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector ("sttp", dissect_sttp, proto_sttp);
}

/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void proto_reg_handoff_sttp(void)
{
  dissector_handle_t sttp_handle;
  sttp_handle = create_dissector_handle(dissect_sttp, proto_sttp);
  dissector_add_uint("udp.port", global_sttp_port, sttp_handle);
}

/* Code to actually dissect the packets */
static void dissect_sttp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *sttp_tree;
  guint32 sttp_pool;
  guint32 sttp_thunk;
  guint32 sttp_offset;
  guint32 sttp_len;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "STTP");

  sttp_pool   = tvb_get_ntohl(tvb, 0);
  sttp_thunk  = tvb_get_ntohl(tvb, 4);
  sttp_offset = tvb_get_ntohl(tvb, 8);
  sttp_len    = tvb_get_ntohl(tvb, 12);

  if(sttp_offset==0 && sttp_len==0)
    col_add_fstr (pinfo->cinfo, COL_INFO, "NoData (Pool %d Atom %d)", sttp_pool, sttp_thunk);
  else
    col_add_fstr (pinfo->cinfo, COL_INFO,
                  "Data (Pool %d Atom %d Offset %d Length %d)",
                  sttp_pool, sttp_thunk, sttp_offset, sttp_len);

  if(tree)
  {
    ti = proto_tree_add_item(tree, proto_sttp, tvb, 0, 16, FALSE);
    sttp_tree = proto_item_add_subtree(ti, ett_sttp);
    ti = proto_tree_add_item(sttp_tree, hf_sttp_pool, tvb, 0, 4, FALSE);
    ti = proto_tree_add_item(sttp_tree, hf_sttp_thunk, tvb, 4, 4, FALSE);
    ti = proto_tree_add_item(sttp_tree, hf_sttp_offset, tvb, 8, 4, FALSE);
    ti = proto_tree_add_item(sttp_tree, hf_sttp_len, tvb, 12, 4, FALSE);
  }
}

