% :- debug.
% :- table(r2calls/2).
% :- table(r2funcByIdx/2).
% :- table(r2funcName/2).
% :- table(r2funcAddr/2).
% :- table(r2nameToReloc/2).
:- use_module(library(http/json)).
:- use_module(library(http/json_convert)).
:- set_prolog_stack(global, limit(100 000 000 000)).
:- set_prolog_stack(trail,  limit(20 000 000 000)).
:- set_prolog_stack(local,  limit(8 000 000 000)).

:- op(995, xfy, [':?']).
:- op(995, xfy, [':*']).
:- op(996, xfy, ['?sz']).
% :- dynamic r2funcs/1.
% :- dynamic r2_imp_fs/2.
% :- dynamic r2_state/1.

:?(LIST, EL) :- nth0(_, LIST, EL).
:*((LIST=ELS), FN) :- findall(EL, (LIST :? EL, call(FN, EL)), ELS).
?sz(LIST,SZ) :- length(LIST,SZ).

r2(InStr) :-
    r2_state(R),
    write(R.in, InStr), nl(R.in),
    flush_output(R.in).
r2p(InStr) :-
    r2_state(R),
    write(R.in, InStr), nl(R.in),
    flush_output(R.in),
    read_string(R.out, "", "", _, OutStr), % read_string(R.out, "\x00", "", _, OutStr),
    format("~w", OutStr).
r2c(InStr) :-
    r2(InStr),
    string_concat(CMD, _, InStr), string_length(CMD,1),
    r2p(CMD), !.

r2flush() :-
    r2_state(R),
    read_string(R.out, "", "", _, OutStr), % read_string(R.out, "\x00", "", _, OutStr),
    format("~w~n^ flushed", OutStr).

r2(InStr, OutJson) :-
    r2_state(R),
    write(R.in, InStr), nl(R.in),
    flush_output(R.in),
    %atom_json_dict(String, OutJson, []).
    %json_read_dict(R.out, OutJson, []),
    json_read(R.out, EOutJson, []),
    json_to_prolog(EOutJson, OutJson),
    read_string(R.out, "", "", _, _).

r2cleanup() :- 
    r2_state(R),
    r2(q),
    close(R.out, [force(true)]),
    close(R.in, [force(true)]),
    process_release(R.pid),
    retractall(r2_state(_)).

r2_addr_setJit(avm, 0x14007d830).
r2_addr_setJit(pepC, 0x1801f3330).
r2_addr_setJit(pep64, 0x1802238d0).
r2_addr_setJit(pep371, 0x180223ab0).
r2_addr_verifyJit(pepC, 0x18021dd00).
r2_addr_verifyJit(pep64, 0x180223ac0).
r2_addr_verifyJit(pep371, 0x180223ca0).
r2imp(avm) :- 
    r2import(avm, "/home/yuri/rs/vm/share/avm_rel/avm.exe").
r2imp(pep64) :- 
    r2import(pep64, "/home/yuri/dv/cpp/flexbot/flash/pepflashplayer.dll").
r2imp(pepC) :- 
    r2import(pepC, "/home/yuri/dl/doclient/pepflashplayer64_26_0_0_137.dll").
r2imp(pep371) :- 
    r2import(pep371, "/home/yuri/dv/cpp/golem/dat/bin/pp64_32.dll").
r2imp() :-
    ID = pep64,
    r2imp(ID),
    r2cleanup,
    string_concat(ID, '.state', NewStateFile),
    qsave_program(NewStateFile, []).

r2import(ID, FILE) :-
    r2open(FILE),
    r2c(aa),r2c(aac),r2c(aar),
    r2(aflj,FUNCS),
    % tell('r2funcs.pl'),
    % write('r2funcs(FUNCS) :- FUNCS = '), write_term(FUNCS, [max_depth(0),quoted(true)]), writeln('.'), told,
    %consult(r2funcs).
    asserta(r2_imp_fs(ID, FUNCS)),
    r2_sel_inst(ID).

% fast_term_serialized(r2funcs(_), STR), tell('r2funcs.pl'), writeln(STR).
% fast_write(Out, r2funcs(_)).

r2func(FUNCS, F) :- r2funcs(FUNCS), FUNCS :? F.
r2func(F) :- r2funcByIdx(_,F).
r2funcByIdx(IDX, F) :- r2funcs(FUNCS), nth0(IDX, FUNCS, json(F)).
r2_sel_inst(ID) :- r2_imp_fs(ID, FUNCS), retractall(r2funcs(_)), asserta(r2funcs(FUNCS)).
r2funcName(F, NAME) :- r2func(F), F :? (name=NAME).
r2funcAddr(F, ADDR) :- r2func(F), F :? (offset=ADDR).
r2funcAttr(F, ATTR) :- r2func(F), F :? ATTR.

r2callby(F, CALLER) :- F :? (codexrefs=L), L :? json(XREF), XREF :? (type='CALL'), XREF :? (addr=CALLER), format("0x~16r~n", CALLER). 
r2calls(F, CALLER, NAME) :- r2funcName(FREF, NAME), r2funcAddr(FREF, CALLER), r2func(F), F :? (callrefs=L), L :? json(XREF), XREF :? XREF :? (addr=CALLER).
r2calls(F, CALLERS) :- r2func(F), F :? (callrefs=L), findall(CALLER, (L :? json(XREF), XREF :? (type='CALL'), XREF :? (addr=CALLER)), CALLERS).

r2nameToReloc(NAME, RELOC_ADDR) :- r2funcName(F, NAME), F :? (callrefs=L), L :? json(CALLREF), CALLREF :? (addr=RELOC_ADDR).


r2callby(CALLER) :- (F=([offset=6444495664, name='fcn.1801f3330', size=59, 'is-pure'=false, realsz=59, noreturn= @(false), stackframe=40, calltype=amd64, cost=20, cc=0, bits=64, type=fcn, nbbs=1, edges=1, ebbs=0, signature='fcn.1801f3330 (int64_t arg_8h);', minbound=6444495664, maxbound=6444495723, callrefs=[json([addr=6444846144, type='CALL', at=6444495691]), json([addr=6444663360, type='CALL', at=6444495699]), json([addr=6444845216, type='CODE', at=6444495718])], datarefs=[6464942752], codexrefs=[json([addr=6444670400, type='CALL', at=6444495664]), json([addr=6444670540, type='CALL', at=6444495664])], dataxrefs=[], indegree=2, outdegree=2, nlocals=0, nargs=1, bpvars=[], spvars=[json([name=arg_8h, kind=arg, type=int64_t, ref=json([base=rsp, offset=8])])], regvars=[], difftype=new])), r2callBy(F, CALLER).
    

r2o() :- r2open("/home/yuri/rs/vm/share/avm_rel/avm.exe").
% r2open() :- r2open("/home/yuri/dv/cpp/flexbot/flash/pepflashplayer.dll"),r2("af @ 0x1802238d0"),r2(aa).
% r2o() :- r2open("/home/yuri/dv/cpp/flexbot/flash/pepflashplayer.dll").
r2open(BinFile) :-
    retractall(r2_state(_)),
    r2open(BinFile, with_cleanup).
r2open(BinFile, with_cleanup) :-
    process_create(path(r2), [ "-q0", "-2", file(BinFile) ],
                   [ stdout(pipe(Out)),
		     stderr(pipe(_)),
		     stdin(pipe(In)),
		     process(Pid)
                   ]),
    dict_create(R, r2instance, [pid:Pid, in:In, out:Out]),
    asserta(r2_state(R)),
    %r2(aa),r2(aac),r2(aar),
    r2p(i).
    


% :- r2open().
