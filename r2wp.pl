:- debug.
% :- table(r2/2).
:- use_module(library(http/json)).
:- use_module(library(http/json_convert)).

r2(InStr) :-
    r2state(R),
    writeln(R.in, InStr),
    flush_output(R.in).
r2p(InStr) :-
    r2state(R),
    writeln(R.in, InStr),
    flush_output(R.in),
    read_string(R.out, "", "", _, OutStr), % read_string(R.out, "\x00", "", _, OutStr),
    format("~w", OutStr).
r2c(InStr) :-
    r2(InStr),
    string_concat(CMD, _, InStr), string_length(CMD,1),
    r2p(CMD), !.

r2flush() :-
    r2state(R),
    read_string(R.out, "", "", _, OutStr), % read_string(R.out, "\x00", "", _, OutStr),
    format("~w~n^ flushed", OutStr).

r2(InStr, OutJson) :-
    r2state(R),
    write(R.in, InStr), nl(R.in),
    flush_output(R.in),
    % json_read_dict(R.out, OutJson, []).
    json_read(R.out, OutJson, []),
    read_string(R.out, "", "", _, _).
    % read_string(R.out, "", "", _, OutStr), % read_string(R.out, "\x00", "", _, OutStr),
    % catch(json_read(R.out, OutJson, [end_of_file(end_of_file)]), Xc, format("Exc (json_read_dict): ~w", Xc)).

r2cleanup() :- 
    r2state(R),
    r2("q"),
    close(R.out, [force(true)]),
    close(R.in, [force(true)]),
    process_release(R.pid),
    abolish(r2state, 1).

% r2open() :- r2open("/home/yuri/rs/vm/share/avm_rel/avm.exe").
% r2open() :- r2open("/home/yuri/dv/cpp/flexbot/flash/pepflashplayer.dll"),r2("af @ 0x1802238d0"),r2(aa).
r2o() :- r2open("/home/yuri/dv/cpp/flexbot/flash/pepflashplayer.dll").
r2open(BinFile) :-
    abolish(r2state, 1),
    r2open(BinFile, with_cleanup).
r2open(BinFile, with_cleanup) :-
    process_create(path(r2), [ "-q0", "-2", file(BinFile) ],
                   [ stdout(pipe(Out)),
		     stderr(pipe(_)),
		     stdin(pipe(In)),
		     process(Pid)
                   ]),
    dict_create(R, r2instance, [pid:Pid, in:In, out:Out]),
    assertz(r2state(R)),
    %r2(aa),r2(aac),r2(aar),
    r2p(i).
    


% :- r2open().
