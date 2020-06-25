:- debug.
% :- table(r2func_import/1).
:- use_module(library(http/json)).
:- use_module(library(http/json_convert)).
:- set_prolog_stack(global, limit(100 000 000 000)).
:- set_prolog_stack(trail,  limit(20 000 000 000)).
:- set_prolog_stack(local,  limit(4 000 000 000)).

:- op(995, xfy, [':?']).

:?(LIST, EL) :- member(EL,LIST).

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
    % json_read_dict(R.out, OutJson, []).
    json_read(R.out, OutJson, []),
    read_string(R.out, "", "", _, _).
    % read_string(R.out, "", "", _, OutStr), % read_string(R.out, "\x00", "", _, OutStr),
    % catch(json_read(R.out, OutJson, [end_of_file(end_of_file)]), Xc, format("Exc (json_read_dict): ~w", Xc)).

r2cleanup() :- 
    r2_state(R),
    r2(q),
    close(R.out, [force(true)]),
    close(R.in, [force(true)]),
    process_release(R.pid),
    abolish(r2_state, 1).

r2_addr_setJit(avm, 0x14007d830).
r2_addr_setJit(pepC, 0x1801f3330).
r2_addr_setJit(pep64, 0x1802238d0).
r2_addr_setJit(pep371, 0x180223ab0).
r2_addr_verifyJit(pepC, 0x18021dd00).
r2_addr_verifyJit(pep64, 0x180223ac0).
r2_addr_verifyJit(pep371, 0x180223ca0).
r2imp(avm) :- 
    r2func_import(avm, "/home/yuri/rs/vm/share/avm_rel/avm.exe").
r2imp(pep64) :- 
    r2func_import(pep64, "/home/yuri/dv/cpp/flexbot/flash/pepflashplayer.dll").
r2imp(pepC) :- 
    r2func_import(pepC, "/home/yuri/dl/doclient/pepflashplayer64_26_0_0_137.dll").
r2imp(pep371) :- 
    r2func_import(pep371, "/home/yuri/dv/cpp/golem/dat/bin/pp64_32.dll").

r2func_import(ID, FILE) :-
    r2open(FILE),
    r2c(aa),r2c(aac),r2c(aar),
    r2(aflj,FUNCS),
    assertz(r2_imp_fs(ID, FUNCS)).
    

r2o() :- r2open("/home/yuri/rs/vm/share/avm_rel/avm.exe").
% r2open() :- r2open("/home/yuri/dv/cpp/flexbot/flash/pepflashplayer.dll"),r2("af @ 0x1802238d0"),r2(aa).
% r2o() :- r2open("/home/yuri/dv/cpp/flexbot/flash/pepflashplayer.dll").
r2open(BinFile) :-
    abolish(r2_state, 1),
    r2open(BinFile, with_cleanup).
r2open(BinFile, with_cleanup) :-
    process_create(path(r2), [ "-q0", "-2", file(BinFile) ],
                   [ stdout(pipe(Out)),
		     stderr(pipe(_)),
		     stdin(pipe(In)),
		     process(Pid)
                   ]),
    dict_create(R, r2instance, [pid:Pid, in:In, out:Out]),
    assertz(r2_state(R)),
    %r2(aa),r2(aac),r2(aar),
    r2p(i).
    


% :- r2open().
