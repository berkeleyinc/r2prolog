:- op(995, xfy, [':?']).
:- op(995, xfy, [':*']).
:- op(996, xfy, ['?sz']).
% :- dynamic r2funcs/1.
% :- dynamic r2_imp_fs/2.
% :- dynamic r2_state/1.

:?(LIST, EL) :- nth0(_, LIST, EL).
:*((LIST=ELS), FN) :- findall(EL, (LIST :? EL, call(FN, EL)), ELS).

% count number N of instances of X in a list L
element_count(X,N,L) :-
    aggregate(count,member(X,L),N).
% count number N of instances of X in a list L, for highest N
max_element_count(X,N,L) :-
    aggregate(max(N1,X1),element_count(X1,N1,L),max(N,X)).


% find XOR_SECRET:
% fnc(_FSLEEP), _{name:'sub.KERNEL32.dll_Sleep'} :< _FSLEEP, nth0(0,_FSLEEP.calls,RELOC), fnc(F), _{nargs:3} :< F, (F.calls=CS) :* [X]>>(X==RELOC),length(CS,CSL),CSL==3,findall(DATPTR, F.datauses :? DATPTR, DATPTRS),max_element_count(XPTR,N,DATPTRS).
