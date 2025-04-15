'''
The log journal in go-ethereum/core/state/journal.go doesn't remove reverted items but
just tracks them in the list. When reverts happen and we have to mark our own log journal
entries as reverted, we want to make sure we index them correctly based on an offset from 
the real journal.
'''
journal = []
journal_ = []
offset = 0

def add_to_journal(n):
    global journal
    global journal_
    print("add_to_journal("+str(n)+")")
    for _ in range(n):
        journal.append( () )
        journal_.append( ((), False) )


def find_reverse_offset(idx, prev):
    o = prev
    for i in range(idx+prev, -1, -1):
        if o < 0: raise Exception("offset less than 0")
        if journal_[i][1] == True:
            o -= 1
        else: return o

    if o != 0:
        raise Exception("Everything reverted, but offset isn't 0")
    if o == prev:
        raise Exception("find was called on an element that isn't reverted because offset is the same.")
    return o


def revert(i):
    global journal
    global journal_
    global offset
    print('revert('+str(i)+')')
    o = offset
    for i in range(len(journal)-1,i-1,-1):
        print('o='+str(o))
        print('i='+str(i))
        if journal_[i+o][1] == True:
            o = find_reverse_offset(i, o)
            if not (journal_[i+o][1] == False and journal_[i+o+1][1] == True):
                raise Exception("Offset compute is off")
        journal_[i+o] = (journal_[i+o][0], True)
        offset += 1
    journal = journal[:i]

def pjj():
    contents = ", ".join( ["ø" if x[1] else "o" for x in journal_]) 
    print("j_ = [ " + contents + "]")

def pj():
    contents = ", ".join( ["o" for x in journal])
    print("j =  [ " + contents + "]")

add_to_journal(5)
pj()
pjj()
revert(3)
pj()
pjj()
add_to_journal(3)
pj()
pjj()
revert(5)
pj()
pjj()
add_to_journal(3)
pj()
pjj()
revert(3)
pj()
pjj()
add_to_journal(4)
pj()
pjj()
revert(5)
pj()
pjj()
revert(2) 
pj()
pjj()

