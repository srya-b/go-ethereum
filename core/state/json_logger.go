package state

import (
    "os"
    "fmt"
    "io/ioutil"
    "encoding/json"

    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/log"
)

func (s *StateDB) preFn(n int) (bool, string) {
	if len(s.logDir) == 0 {
		//panic("Log dir not set")
		log.Error("Log dir not set")
		return false, ""
	}
	//log.Info("File name", "logDir", s.logDir, "blockNo", s.blockNo, "n", n)
	//log.Info("Completed", "fmt", fmt.Sprintf("%s/predata-%v-%d.json", s.logDir, s.blockNo, n))
	return true, fmt.Sprintf("%s/predata-%v-%d.json", s.logDir, s.blockNo, n)
}

func (s *StateDB) postFn(n int) (bool, string) {
	if len(s.logDir) == 0 {
		//panic("Log dir not set")
		log.Error("Log dir not set")
		return false, ""
	}
	//log.Info("File name", "logDir", s.logDir, "blockNo", s.blockNo, "n", n)
	//log.Info("Completed", "fmt", fmt.Sprintf("%s/postdata-%v-%d.json", s.logDir, s.blockNo, n))
	return true, fmt.Sprintf("%s/postdata-%v-%d.json", s.logDir, s.blockNo, n)
}

func createAndOpenFile(fn string) (bool, *os.File) {
	file, err := os.OpenFile(fn, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		log.Error("Failed to createAndOpenFile", "fn", fn, "err", err)
		//panic(err)
		return false, nil
	}
	return true, file
}

func (s *StateDB) writePreData(data []byte) bool {
    s.numPre++
	//log.Info("WRITE PRE DATA", "fn", s.preFn(s.numPre))
	success, fn := s.preFn(s.numPre)
	if !success {
		log.Error("writePreData failure")
		return false
	}

    success, f := createAndOpenFile(fn)
	if !success {
		log.Error("writepredata failed")
		return false
	}

    defer f.Close()
	_, err := f.Write(data)
	if err != nil {
		log.Error("File write error", "fn", fn, "err", err)
		//panic(err)
		return false
	}
	return true
}

func (s *StateDB) writePostData(data []byte) bool {
    s.numPost++
	success, fn := s.postFn(s.numPost)
	if !success {
		log.Error("write post Data faile")
		return false
	}

	log.Info("WRITE POST DATA", "dn", fn)
    success, f := createAndOpenFile(fn)
	if !success {
		log.Error("write post data failed")
		return false
	}

    defer f.Close()
    _, err := f.Write(data)
    if err != nil {
		log.Error("File write failure post data", "fn", fn, "err", err)
        //panic(err)
		return false
    }
	return true
}

func (s *StateDB) readPreData(n int) []byte {
    if s.numPre > 0 && n <= s.numPre {
		_, fn := s.preFn(n)
        f, err := os.Open(fn)
        if err != nil {
            panic(err)
        }
        defer f.Close()

        content, err := ioutil.ReadFile(fn)
        if err != nil {
            panic(err)
        }
        return content
    } else {
        return nil
    }
}

func (s *StateDB) readPostData(n int) []byte {
    if s.numPost > 0 && n <= s.numPost {
		_, fn := s.postFn(n)
        f, err := os.Open(fn)
        if err != nil {
            panic(err)
        }
        defer f.Close()

        content, err := ioutil.ReadFile(fn)
        if err != nil {
            panic(err)
        }
        return content
    } else {
        return nil
    }
}

func (s *StateDB) printPre(n int, truth [][]LogJournalEntry) {
	rawData := s.readPreData(1)
	var preObj PreLog
	err := json.Unmarshal(rawData, &preObj)
	if err != nil {
		log.Error("Couldn't unmarshal data")
		panic(err)
	}

	log.Info("Actual journal data", "data", truth[0][0:4])
	log.Info("From json", "data", preObj.Journals[0][0:4])
}

func (s *StateDB) printPostAndCheck(n int, truth map[common.Address][]common.Hash) {
    rawData := s.readPostData(1)
    var postObj PostLog
    err := json.Unmarshal(rawData, &postObj)
    if err != nil {
        log.Error("Couldn't unmarshal post data")
        panic(err)
    }

    for addr := range truth {
        _, ok := postObj.Accounts[addr]
        if !ok {
            log.Error("Address in accounts but not in marshaled data", "addr", addr, "len", len(postObj.Accounts))
            panic("doesn't exist")
        }
    }

    i := 0
    for addr, paths := range postObj.Accounts {
        if i > 4 {
            break
        }
        log.Error("Entry in postData", "idx", i, "addr", addr, "paths", paths)
        i++
    }
}




