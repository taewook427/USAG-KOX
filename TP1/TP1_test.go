// go test
package TP1

import (
	"bytes"
	"fmt"
	"sync"
	"testing"

	"github.com/k-atusa/USAG-Lib/Opsec"
)

func SendTest(wg *sync.WaitGroup) {
	defer wg.Done()
	var err error
	defer func() {
		if err == nil {
			fmt.Println("send success")
		} else {
			fmt.Println(err)
		}
	}()
	sock := new(TCPsocket)
	err = sock.MakeConnection("127.0.0.1:8080")
	defer sock.Close()
	if err != nil {
		return
	}

	data := make([]byte, 1048576)
	tp := new(TP1)
	tp.Init(HASH_ARG2+SYM_GCM1+ASYM_PQC1, true, true, []byte("secret"), sock.Conn)
	fromPub, toPub, err := tp.Send(bytes.NewReader(data), int64(len(data)), "secret")
	if err != nil {
		return
	}
	fmt.Println("from: " + Opsec.Crc32(fromPub) + " to: " + Opsec.Crc32(toPub))
}

func RecvTest(wg *sync.WaitGroup) {
	defer wg.Done()
	var err error
	defer func() {
		if err == nil {
			fmt.Println("recv success")
		} else {
			fmt.Println(err)
		}
	}()
	sock := new(TCPsocket)
	err = sock.MakeListener("8080")
	defer sock.Close()
	if err != nil {
		return
	}

	tp := new(TP1)
	tp.Init(0, true, true, []byte("secret"), sock.Conn)
	dst := new(bytes.Buffer)
	fromPub, toPub, smsg, err := tp.Receive(dst)
	if err != nil {
		return
	}
	fmt.Println(bytes.Equal(make([]byte, 1048576), dst.Bytes()))
	fmt.Println(smsg == "secret")
	fmt.Println("from: " + Opsec.Crc32(fromPub) + " to: " + Opsec.Crc32(toPub))
}

func TestMain(m *testing.M) {
	// 1. helpers
	ips, err := GetIPs(false)
	if err == nil {
		for _, ip := range ips {
			fmt.Println(ip)
		}
	} else {
		fmt.Println(err)
	}
	fmt.Println(GetPath())
	fmt.Println(CleanPath("<path>\\.txt"))
	fmt.Println(TempPath())
	fmt.Println(DelPath("path.txt"))

	// 2. protocol
	wg := sync.WaitGroup{}
	wg.Add(2)
	go SendTest(&wg)
	go RecvTest(&wg)
	wg.Wait()
}
