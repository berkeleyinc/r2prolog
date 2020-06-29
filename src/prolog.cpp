#include "prolog.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <unordered_map>
#include <vector>

#include "R2Utils.h"
#include <r_cmd.h>

#include "scope.hpp"

#include <SWI-Prolog.h>
#include <SWI-cpp.h>

using namespace std;

namespace {
struct {
  unordered_map<unsigned long long, RAnalFunction *> funcs;
  vector<RAnalFunction *> funcsVec;
  unordered_map<unsigned long long, RAnalRef *> xrefs, xrefs_at;
  vector<RAnalRef *> xrefsVec;
  vector<RAnalFunction *> xrefsToFuncVec;
  RCore *core;
} _r2;
struct {
} _pl;
} // namespace

int r2_init(RCore *core, const char *input) {
  printf("r2prolog initialize!\n");
  _r2.core = core;
  // char *av[10];
  // int ac = 0;
  // av[ac++] = const_cast<char *>("r2");
  // av[ac++] = const_cast<char *>("-q");
  // av[ac] = NULL;
  // if (!PL_initialise(ac, av))
  //   PL_halt(1);
  // cerr << "SWI PROLOG READY\n";

  return 1;
}
int r2_fini(RCore *user, const char *input) {
  printf("r2prolog destruction.\n");

  return 1;
}

void import_r2_data(RCore *core);
void r2_cmd(RCore *core, const char *input) {
  _r2.core = core;

  // string inp = input;
  // if (!inp.empty()) {
  //   string ans;
  //   _pl.s->query_string(inp, ans);
  //   cerr << "ans: " << ans << endl;
  //   return;
  // }

  printf("PPL called from r2prolog.\n");
  r_cmd_call(core->rcmd, "aa");
  r_cmd_call(core->rcmd, "aac");
  r_cmd_call(core->rcmd, "aar");
  import_r2_data(core);

  // for (;;) {
  //   int status = PL_toplevel() ? 0 : 1;
  //   PL_halt(status);
  // }

  // string fn_name;
  // auto q = _pl.s->query("fnc", any(), var(fn_name), any());
  // while (!q->done()) {
  //   cout << "Function name: " << fn_name << endl;
  //   q->next();
  // }
  // _pl.s->print_predicate(cout, "fnc", 3);

  // _pl.s->add_fact("plugin", 1);
  // _pl.s->add_fact("plugin", 2);
  // _pl.s->print_predicate(cout, "plugin", 1);
  // int cid;
  // auto q = _pl.s->query("plugin", var(cid));
  // while (!q->done()) {
  //   cout << "GOT QUERY RESULT: " << cid << endl;
  //   q->next();
  // }
}
const char *getRealRef(RCore *core, ut64 off) {
  RFlagItem *item;
  RListIter *iter;

  const RList *list = r_flag_get_list(core->flags, off);
  if (!list) {
    return NULL;
  }

  const char *ref_name = nullptr;
  r_list_foreach_cpp<RFlagItem>(list, [&ref_name](auto item) {
    if (!item->name || strncmp(item->name, "sym.", 4)) {
      return;
    }
    ref_name = item->name;
  });

  return ref_name;
}

/*
 *
        RListIter *iter;
        RAnalRef *refi;
        RList *refs, *xrefs;
        if (!pj) {
                return -1;
        }
        int ebbs = 0;
        pj_o (pj);
        pj_kn (pj, "offset", fcn->addr);
        char *name = r_core_anal_fcn_name (core, fcn);
        if (name) {
                pj_ks (pj, "name", name);
        }
        pj_kn (pj, "size", r_anal_function_linear_size (fcn));
        pj_ks (pj, "is-pure", r_str_bool (r_anal_function_purity (fcn)));
        pj_kn (pj, "realsz", r_anal_function_realsize (fcn));
        pj_kb (pj, "noreturn", fcn->is_noreturn);
        pj_ki (pj, "stackframe", fcn->maxstack);
        if (fcn->cc) {
                pj_ks (pj, "calltype", fcn->cc); // calling conventions
        }
        pj_ki (pj, "cost", r_anal_function_cost (fcn)); // execution cost
        pj_ki (pj, "cc", r_anal_function_complexity (fcn)); // cyclic cost
        pj_ki (pj, "bits", fcn->bits);
        pj_ks (pj, "type", r_anal_fcntype_tostring (fcn->type));
        pj_ki (pj, "nbbs", r_list_length (fcn->bbs));
        pj_ki (pj, "edges", r_anal_function_count_edges (fcn, &ebbs));
        pj_ki (pj, "ebbs", ebbs);
        {
                char *sig = r_core_cmd_strf (core, "afcf @ 0x%"PFMT64x,
 fcn->addr); if (sig) { r_str_trim (sig); pj_ks (pj, "signature", sig); free
 (sig);
                }

        }
        pj_kn (pj, "minbound", r_anal_function_min_addr (fcn));
        pj_kn (pj, "maxbound", r_anal_function_max_addr (fcn));

        int outdegree = 0;
        refs = r_anal_function_get_refs (fcn);
        if (!r_list_empty (refs)) {
                pj_k (pj, "callrefs");
                pj_a (pj);
                r_list_foreach (refs, iter, refi) {
                        if (refi->type == R_ANAL_REF_TYPE_CALL) {
                                outdegree++;
                        }
                        if (refi->type == R_ANAL_REF_TYPE_CODE ||
                                refi->type == R_ANAL_REF_TYPE_CALL) {
                                pj_o (pj);
                                pj_kn (pj, "addr", refi->addr);
                                pj_ks (pj, "type", r_anal_xrefs_type_tostring
 (refi->type)); pj_kn (pj, "at", refi->at); pj_end (pj);
                        }
                }
                pj_end (pj);

                pj_k (pj, "datarefs");
                pj_a (pj);
                r_list_foreach (refs, iter, refi) {
                        if (refi->type == R_ANAL_REF_TYPE_DATA) {
                                pj_n (pj, refi->addr);
                        }
                }
                pj_end (pj);
        }
        r_list_free (refs);

        int indegree = 0;
        xrefs = r_anal_function_get_xrefs (fcn);
        if (!r_list_empty (xrefs)) {
                pj_k (pj, "codexrefs");
                pj_a (pj);
                r_list_foreach (xrefs, iter, refi) {
                        if (refi->type == R_ANAL_REF_TYPE_CODE ||
                                refi->type == R_ANAL_REF_TYPE_CALL) {
                                indegree++;
                                pj_o (pj);
                                pj_kn (pj, "addr", refi->addr);
                                pj_ks (pj, "type", r_anal_xrefs_type_tostring
 (refi->type)); pj_kn (pj, "at", refi->at); pj_end (pj);
                        }
                }

                pj_end (pj);
                pj_k (pj, "dataxrefs");
                pj_a (pj);

                r_list_foreach (xrefs, iter, refi) {
                        if (refi->type == R_ANAL_REF_TYPE_DATA) {
                                pj_n (pj, refi->addr);
                        }
                }
                pj_end (pj);
        }
        r_list_free (xrefs);

        pj_ki (pj, "indegree", indegree);
        pj_ki (pj, "outdegree", outdegree);

        if (fcn->type == R_ANAL_FCN_TYPE_FCN || fcn->type ==
 R_ANAL_FCN_TYPE_SYM) { pj_ki (pj, "nlocals", r_anal_var_count (core->anal, fcn,
 'b', 0) + r_anal_var_count (core->anal, fcn, 'r', 0) + r_anal_var_count
 (core->anal, fcn, 's', 0)); pj_ki (pj, "nargs", r_anal_var_count (core->anal,
 fcn, 'b', 1) + r_anal_var_count (core->anal, fcn, 'r', 1) + r_anal_var_count
 (core->anal, fcn, 's', 1));

                pj_k (pj, "bpvars");
                r_anal_var_list_show (core->anal, fcn, 'b', 'j', pj);
                pj_k (pj, "spvars");
                r_anal_var_list_show (core->anal, fcn, 's', 'j', pj);
                pj_k (pj, "regvars");
                r_anal_var_list_show (core->anal, fcn, 'r', 'j', pj);

                pj_ks (pj, "difftype", fcn->diff->type ==
 R_ANAL_DIFF_TYPE_MATCH?"match": fcn->diff->type ==
 R_ANAL_DIFF_TYPE_UNMATCH?"unmatch":"new"); if (fcn->diff->addr != -1) { pj_kn
 (pj, "diffaddr", fcn->diff->addr);
                }
                if (fcn->diff->name) {
                        pj_ks (pj, "diffname", fcn->diff->name);
                }
        }
        pj_end (pj);
        free (name);

*/

void import_r2_data(RCore *core) {
  printf("%s %d\n", __func__, __LINE__);
  vector<stringstream> vss(5);
  auto &ss_fncs = vss[0];
  auto &ss_xrefs = vss[1];
  auto &ss_refs = vss[2];
  auto &ss_types = vss[3];
  auto &ss_fncs_attrs = vss[4];
  r_list_foreach_cpp<RAnalFunction>(core->anal->fcns, [&](RAnalFunction *fn) {
    cout << fn->name << ": ";
    std::vector<size_t> callby, calls, datarefs;

    auto xrefs = r_anal_function_get_xrefs(fn);
    r_list_foreach_cpp<RAnalRef>(xrefs, [&](auto ref) {
      // printf("xref: %p, ", (void *)ref->at);
      // _r2.xrefs.insert(std::make_pair(ref->addr, ref));
      // _r2.xrefs_at.insert(std::make_pair(ref->at, ref));
      // _r2.xrefsVec.emplace_back(ref);
      // _r2.xrefsToFuncVec.emplace_back(fn);
      // xsb->add_fact("xref", std::string(1, (char)ref->type), fn->addr,
      //               ref->addr, ref->at);
      ss_xrefs << endl
               << "callby(" << fn->addr << "," << ref->addr << ",'"
               << (char)ref->type << "'," << ref->at << ").";
      if (ref->type == R_ANAL_REF_TYPE_CODE ||
          ref->type == R_ANAL_REF_TYPE_CALL) {
        callby.emplace_back(ref->addr);
      }
    });

    auto refs = r_anal_function_get_refs(fn);
    r_list_foreach_cpp<RAnalRef>(refs, [&](auto refi) {
      const char *flag = nullptr;
      if (refi->type == R_ANAL_REF_TYPE_CODE ||
          refi->type == R_ANAL_REF_TYPE_CALL) {
        flag = getRealRef(core, refi->addr);
        calls.emplace_back(refi->addr);
      } else {
        datarefs.emplace_back(refi->addr);
      }
      // if (flag) {
      //   cout << "Ref: " << flag << endl;
      //   // r_list_append (ret, r_str_newf (flag));
      // }

      // xsb->add_fact(refi->type == R_ANAL_REF_TYPE_CALL ? "call_ref"
      //                                                  : "code_ref",
      //               fn->addr, refi->addr, refi->at, flag ? flag : "");
      ss_refs << endl
              << "calls(" << fn->addr << "," << refi->addr << ",'"
              << (char)refi->type << "'," << refi->at << ",'"
              << (flag ? flag : "") << "'"
              << ").";
    });

    // _r2.funcs.insert(std::make_pair(fn->addr, fn));
    // _r2.funcsVec.emplace_back(fn);
    // xsb->add_fact("fnc", fn->addr, fn->name, fn->ninstr);

    auto varsList = r_anal_var_all_list(core->anal, fn);
    if (varsList) {
      ss_types << endl << "fargs(" << fn->addr << ",[";
      int argnum = 0;
      r_list_foreach_cpp<RAnalVar>(varsList, [&](RAnalVar *var) {
        if (argnum > 0)
          ss_types << ",";
        ss_types << "arg{type:'" << (var->type ? var->type : "") << "',name:'"
                 << (var->name ? var->name : "") << "'}";
        argnum++;
      });
      ss_types << "]).";
    }

    cout << "ninstr=" << fn->ninstr << endl;

    ss_fncs_attrs << endl;
    ss_fncs_attrs << "fnc(_{addr:" << fn->addr << ",";
    ss_fncs_attrs << "size:" << r_anal_function_linear_size(fn);
    ss_fncs_attrs << ",realsz:" << r_anal_function_realsize(fn);
    if (fn->name)
      ss_fncs_attrs << ",name:'" << fn->name << "'";
    ss_fncs_attrs << ",ninstr:" << fn->ninstr;
    ss_fncs_attrs << ",nargs:"
                  << r_anal_var_count(core->anal, fn, 'b', 1) +
                         r_anal_var_count(core->anal, fn, 'r', 1) +
                         r_anal_var_count(core->anal, fn, 's', 1);

    int ebbs;
    ss_fncs_attrs << ",nedges:" << r_anal_function_count_edges(fn, &ebbs);
    // ss_fncs_attrs << ",ncalls:" << ncalls;
    // ss_fncs_attrs << ",ncallby:" << ncallby;
    ss_fncs_attrs << ",calls:[";
    for_each(calls.begin(), calls.end(),
             [&ss_fncs_attrs, sep = ' '](auto addr) mutable {
               ss_fncs_attrs << sep << addr, sep = ',';
             });
    ss_fncs_attrs << "],callby:[";
    for_each(callby.begin(), callby.end(),
             [&ss_fncs_attrs, sep = ' '](auto addr) mutable {
               ss_fncs_attrs << sep << addr, sep = ',';
             });
    ss_fncs_attrs << "],datarefs:[";
    for_each(datarefs.begin(), datarefs.end(),
             [&ss_fncs_attrs, sep = ' '](auto addr) mutable {
               ss_fncs_attrs << sep << addr, sep = ',';
             });
    ss_fncs_attrs << "]";
    ss_fncs_attrs << "}).";
    // ss_fncs << endl << "fnc(" << fn->addr << ").";
  });
  ofstream f("facts.pl");
  for_each(vss.begin(), vss.end(), [&f](auto &&ss) { f << ss.str() << endl; });
  f.close();
}

// static foreign_t pl_get_xref(term_t fromAddr, term_t atAddr, term_t xrefType,
//                              control_t handle) {
//   size_t curr_pos = 0;
//   switch (PL_foreign_control(handle)) {
//   case PL_FIRST_CALL:
//     break;
//   case PL_REDO:
//     curr_pos = PL_foreign_context(handle);
//     break;
//   case PL_PRUNED:
//     curr_pos = PL_foreign_context(handle);
//     PL_succeed;
//   }
//
//   RAnalRef *xref = nullptr;
//   do {
//     vector<RAnalRef *> out_refs;
//     if (curr_pos == 0) {
//       long addr;
//       if (PL_get_long(fromAddr, &addr)) {
//         auto it = _r2.xrefs.find(addr);
//         if (it == _r2.xrefs.end())
//           PL_fail;
//         xref = it->second;
//         break;
//       }
//       if (PL_get_long(atAddr, &addr)) {
//         auto it = _r2.xrefs_at.find(addr);
//         if (it == _r2.xrefs_at.end())
//           PL_fail;
//         xref = it->second;
//         break;
//       }
//       char type = 0;
//       {
//         char *type_buf;
//         size_t type_len;
//         if (PL_get_string(xrefType, &type_buf, &type_len))
//           type = type_buf[0];
//       }
//     }
//     // for (auto & ref: _r2.xrefsVec) {
//     // 	// ---
//     // 	if (type && ref->type != type)
//     // 	  continue;
//     // 	out_refs.emplace
//     // }
//     curr_pos++;
//     auto it = _r2.xrefsVec.begin() + curr_pos - 1;
//     xref = *it;
//   } while (false);
//
//   if (PL_is_variable(fromAddr)) {
//     PL_unify_uint64(fromAddr, xref->addr);
//   }
//   if (PL_is_variable(atAddr)) {
//     PL_unify_uint64(atAddr, xref->at);
//   }
//   if (PL_is_variable(xrefType)) {
//     PL_unify_string_chars(xrefType, std::string(1, xref->type).c_str());
//   }
//   if (curr_pos)
//     PL_retry(curr_pos);
//   else
//     PL_succeed;
// }
// static foreign_t pl_get_xrefs(term_t term, int arity, control_t handle) {
//   // printf("%s %d %d\n", __func__, __LINE__, arity);
//
//   if (PL_is_variable(term)) {
//     term_t l = PL_copy_term_ref(term), a = PL_new_term_ref();
//
//     for (auto &ref : _r2.xrefsVec) {
//       if (!PL_unify_list(l, a, l) || !PL_unify_uint64(a, ref->addr))
//         PL_fail;
//     }
//     if (!PL_unify_nil(l))
//       PL_fail;
//   }
//   term++;
//
//   if (arity >= 2 && PL_is_variable(term)) {
//     term_t l = PL_copy_term_ref(term), a = PL_new_term_ref();
//
//     for (auto &ref : _r2.xrefsVec) {
//       if (!PL_unify_list(l, a, l) || !PL_unify_uint64(a, ref->at))
//         PL_fail;
//     }
//     if (!PL_unify_nil(l))
//       PL_fail;
//   }
//   term++;
//
//   if (arity >= 3 && PL_is_variable(term)) {
//     term_t l = PL_copy_term_ref(term), a = PL_new_term_ref();
//
//     for (auto &fn : _r2.xrefsToFuncVec) {
//       if (!PL_unify_list(l, a, l) || !PL_unify_uint64(a, fn->addr))
//         PL_fail;
//     }
//     if (!PL_unify_nil(l))
//       PL_fail;
//   }
//
//   return true;
// }
// static foreign_t pl_get_funcs(term_t term, int arity, control_t handle) {
//   printf("%s %d %d\n", __func__, __LINE__, arity);
//
//   if (PL_is_variable(term)) {
//     term_t l = PL_copy_term_ref(term), a = PL_new_term_ref();
//
//     for (auto &fn : _r2.funcsVec) {
//       if (!PL_unify_list(l, a, l) || !PL_unify_uint64(a, fn->addr))
//         PL_fail;
//     }
//     if (!PL_unify_nil(l))
//       PL_fail;
//   printf("GEN0 %s %d %d\n", __func__, __LINE__, arity);
//   }
//   term++;
//   if (arity >= 2 && PL_is_variable(term)) {
//     term_t l = PL_copy_term_ref(term), a = PL_new_term_ref();
//
//     for (auto &fn : _r2.funcsVec) {
//       if (!PL_unify_list(l, a, l) || !PL_unify_uint64(a, fn->ninstr))
//         PL_fail;
//     }
//     if (!PL_unify_nil(l))
//       PL_fail;
//   printf("GEN1 %s %d %d\n", __func__, __LINE__, arity);
//   }
//   term++;
//   if (arity >= 3 && PL_is_variable(term)) {
//     term_t l = PL_copy_term_ref(term), a = PL_new_term_ref();
//
//     for (auto &fn : _r2.funcsVec) {
//       if (!PL_unify_list(l, a, l) || !PL_unify_string_chars(a, fn->name))
//         PL_fail;
//     }
//     if (!PL_unify_nil(l))
//       PL_fail;
//   printf("GEN2 %s %d %d\n", __func__, __LINE__, arity);
//   }
//
//   return true;
// }
// static foreign_t pl_get_func(term_t term, control_t handle) {
//   size_t curr_pos = 0;
//   switch (PL_foreign_control(handle)) {
//   case PL_FIRST_CALL:
//     break;
//   case PL_REDO:
//     curr_pos = PL_foreign_context(handle);
//     break;
//   case PL_PRUNED:
//     curr_pos = PL_foreign_context(handle);
//     PL_succeed;
//   }
//
//   if (PL_is_variable(term)) {
//     // printf("%s: is variable\n", __func__);
//     curr_pos++;
//     if (curr_pos >= _r2.funcsVec.size() - 1)
//       PL_fail;
//     auto it = _r2.funcsVec.begin() + curr_pos - 1;
//     PL_unify_uint64(term, (*it)->addr);
//     PL_retry(curr_pos);
//   }
//
//   long addr;
//   if (!PL_get_long(term, &addr)) {
//     printf(" no func\n");
//     PL_fail;
//   }
//   printf("func: %li\n", addr);
//
//   auto it = _r2.funcs.find(addr);
//   if (it == _r2.funcs.end())
//     PL_fail;
//   else
//     PL_succeed;
// }
//
//
// void import_r2funcs(RCore *core) {
//   printf("%s %d\n", __func__, __LINE__);
//
//   std::stringstream iss[2];
//   auto list = core->anal->fcns;
//   for (RListIter *it = list->head; it; it = it->n) {
//     RAnalFunction *fn = (RAnalFunction *)it->data;
//     cout << fn->name << ": ";
//
//     auto xrefs = r_anal_function_get_xrefs(fn);
//     for (RListIter *it2 = xrefs->head; it2; it2 = it2->n) {
//       RAnalRef *ref = (RAnalRef *)it2->data;
//       // printf("xref: %p, ", (void *)ref->at);
//       _r2.xrefs.insert(std::make_pair(ref->addr, ref));
//       _r2.xrefs_at.insert(std::make_pair(ref->at, ref));
//       _r2.xrefsVec.emplace_back(ref);
//       _r2.xrefsToFuncVec.emplace_back(fn);
//       iss[1] << "xref(" << fn->addr << "," << ref->addr << "," << ref->at <<
// ")." << endl;
//     }
//
//     cout << std::hex << fn->addr << std::dec << ", ";
//     cout << "Instrs: " << fn->ninstr << ", ";
//     if (fn->imports)
//       cout << "Imps: " << fn->imports->length << ", ";
//     cout << endl;
//     _r2.funcs.insert(std::make_pair(fn->addr, fn));
//     _r2.funcsVec.emplace_back(fn);
//      iss[0] << "fnc(" << fn->addr << "," << fn->ninstr << ",'" << fn->name <<
// "')." << endl;
//     // r_list_foreach_cpp(core->anal->fcns, [](auto &fn) {});
//   }
//
//   std::ofstream ofpl("/tmp/r2anal.pl");
//   ofpl << iss[0].str();
//   ofpl << iss[1].str();
// }

/*
void old_r2_cmd(RCore *core, const char *input) {
  printf("PPL called from r2prolog!\n");
  r_cmd_call(core->rcmd, "aaa");

  import_r2funcs(core);

  // PL_register_foreign("fnc", 1, (pl_function_t)pl_get_func,
  //                     PL_FA_NONDETERMINISTIC);
  // PL_register_foreign("xref", 3, (pl_function_t)pl_get_xref,
  //                     PL_FA_NONDETERMINISTIC);
  PL_register_foreign("r2_fncs_list", 1, (pl_function_t)pl_get_funcs,
                      PL_FA_VARARGS);
  PL_register_foreign("r2_fncs_list", 2, (pl_function_t)pl_get_funcs,
                      PL_FA_VARARGS);
  PL_register_foreign("r2_fncs_list", 3, (pl_function_t)pl_get_funcs,
                      PL_FA_VARARGS);
  PL_register_foreign("r2_xrefs_list", 1, (pl_function_t)pl_get_xrefs,
                      PL_FA_VARARGS);
  PL_register_foreign("r2_xrefs_list", 2, (pl_function_t)pl_get_xrefs,
                      PL_FA_VARARGS);
  PL_register_foreign("r2_xrefs_list", 3, (pl_function_t)pl_get_xrefs,
                      PL_FA_VARARGS);

  PlTermv av(1);
  PlQuery q("animal", av);
  while (q.next_solution())
    cout << (char *)av[0] << endl;
  for (;;) {
    int status = PL_toplevel() ? 0 : 1;
    PL_halt(status);
  }
  {
    PlTermv av("1");
    PlQuery q("atom_checksum", av);
    while (q.next_solution())
      cout << (char *)av[0] << endl;
  }
}
*/
