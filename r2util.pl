:- op(995, xfy, [':?']).
:- op(995, xfy, [':*']).
:- op(996, xfy, [':#?']).
:- op(986, xfy, [':##']).
% :- dynamic r2funcs/1.
% :- dynamic r2_imp_fs/2.
% :- dynamic r2_state/1.

:?(LIST, EL) :- nth0(_, LIST, EL).
:*((LIST=ELS), FN) :- findall(EL, (LIST :? EL, call(FN, EL)), ELS).
:#?(LIST, EL) :- length(LIST, EL).
:##(NUM, HEX) :- format(atom(HEX), '0x~16r', [NUM]).

% count number N of instances of X in a list L
element_count(X,N,L) :-
    aggregate(count,member(X,L),N).
% count number N of instances of X in a list L, for highest N
max_element_count(X,N,L) :-
    aggregate(max(N1,X1),element_count(X1,N1,L),max(N,X)).


% find XOR_SECRET:
% fnc(_FSLEEP), _{name:'sub.KERNEL32.dll_Sleep'} :< _FSLEEP, nth0(0,_FSLEEP.calls,RELOC), fnc(F), _{nargs:3} :< F, (F.calls=CS) :* [X]>>(X==RELOC),length(CS,CSL),CSL==3,findall(DATPTR, F.datauses :? DATPTR, DATPTRS),max_element_count(XPTR,N,DATPTRS).

xorSecret(XPTR) :-
    fnc(_FSLEEP), _FSLEEP.name == 'sub.KERNEL32.dll_Sleep', nth0(0,_FSLEEP.calls,RELOC),
    fnc(F), _{nargs:3} :< F, (F.calls=CS) :* [X]>>(X==RELOC),length(CS,3),
    findall(DATPTR, F.datarefs :? DATPTR, DATPTRS),
    max_element_count(XPTR,N,DATPTRS), !.
% pep64:
% FSJ = {addr:6444693712, callby:[6444694339, 6444693735], calls:[6444693754, 6464835928, 6444876352], datarefs:[6444239424, 6444692192], name:'fcn.1802238d0', nargs:1, ninstr:24, realsz:107, size:107},
% FVJ = {addr:6444694208, callby:[6444242606, 6444688522, 6444688850, 6444689074, 6444689298, 6444689522, 6444689746, 6444689970, 6444694328, 6444694416, 6444694357, 6444694344, 6444694473], calls:[6444516832, 6444241616, 6444559600, 6444694349, 6444693712, 6444694499, 6444694475, 6444517968, 6453247648, 6444694457, 6443987248, 6444242784, 6443992960, 6444694499, 6444240256, 6444517968], datarefs:[6465037280], name:'fcn.180223ac0', nargs:5, ninstr:79, realsz:326, size:326}
% pepC
% FSJ = {addr:6444495664, callby:[6444670400, 6444670540], calls:[6444846144, 6444663360, 6444845216], datarefs:[6464942752], name:'fcn.1801f3330', nargs:1, ninstr:15, realsz:59, size:59},
% FVJ = {addr:6444670208, callby:[6444222462, 6444664570, 6444664898, 6444665122, 6444665346, 6444665570, 6444665794, 6444666018, 6444670328, 6444670452, 6444670393, 6444670380, 6444670509], calls:[6444494528, 6444221488, 6444536992, 6444670385, 6444849360, 6444670535, 6444670511, 6444495664, 6453183056, 6444670493, 6443970992, 6444222624, 6443976672, 6444670535, 6444220176, 6444495664], datarefs:[6444219280, 6444668224, 6464953632], name:'fcn.18021dd00', nargs:5, ninstr:85, realsz:362, size:362}
fnJitAddrs(VJ, SJ) :-
    SJ_NARGS=1,
    VJ_NCALLS = 16,
    VJ_NCALLBY = 13,
    fnc(F),
    F.addr = SJ,
      F.nargs==SJ_NARGS,
	findall(VJ, calls(VJ, SJ, T, AT, FLAG), POSS), length(POSS, POSS_LEN), [1,2] :? POSS_LEN, POSS :? VJ,
	fnc(FVJ),
	FVJ.addr==VJ,
	    FVJ.nargs==5,
		length(FVJ.calls, VJ_NCALLS),
		length(FVJ.callby, VJ_NCALLBY),
		!.
