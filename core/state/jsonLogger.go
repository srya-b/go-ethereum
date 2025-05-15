package state

import (
    "os"
    "fmt"
    "io/ioutil"
)

func (s *StateDB) preFn(n int) string {
	if len(s.logDir) == 0 {
		panic("Log dir not set")
	}
	return fmt.Sprintf("%s/predata-%s-%s.json", s.logDir, s.blockNo, n)
}

func (s *StateDB) postFn(n int) string {
	if len(s.logDir) == 0 {
		panic("Log dir not set")
	}
	return fmt.Sprintf("%s/postdata-%s-%s.json", s.logDir, s.blockNo, n)
}

func createAndOpenFile(fn string) *os.File {
	file, err := os.OpenFile(fn, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		panic(err)
	}
	return file
}

func (s *StateDB) writePreData(data []byte) {
    s.numPre++
    f := createAndOpenFile(s.preFn(s.numPre))
    defer f.Close()
	_, err := f.Write(data)
	if err != nil {
		panic(err)
	}
}

func (s *StateDB) writePostData(data []byte) {
    s.numPost++
    f := createAndOpenFile(s.postFn(s.numPost))
    defer f.Close()
    _, err := f.Write(data)
    if err != nil {
        panic(err)
    }
}

func (s *StateDB) readPreData(n int) []byte {
    if s.numPre > 0 && n <= s.numPre {
        f, err := os.Open(s.preFn(n))
        if err != nil {
            panic(err)
        }
        defer f.Close()

        content, err := ioutil.ReadFile(s.preFn(n))
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
        f, err := os.Open(s.postFn(n))
        if err != nil {
            panic(err)
        }
        defer f.Close()

        content, err := ioutil.ReadFile(s.postFn(n))
        if err != nil {
            panic(err)
        }
        return content
    } else {
        return nil
    }
}
