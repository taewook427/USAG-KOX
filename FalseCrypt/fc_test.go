// go test
package FalseCrypt

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/k-atusa/USAG-Lib/Bencrypt"
)

func buildPEVFS() *PEVFS {
	// setup basic value
	ckey, wauth := make([]byte, 32), make([]byte, 32)
	copy(ckey, "abcdefghabcdefghabcdefghabcdefgh")
	copy(wauth, "abcdefghabcdefghabcdefghabcdefgh")
	vu := VUser{
		StorageName: "test", UserName: "root", SecureLevel: SL_TOPSECRET,
		UserBitA: "test", UserBitB: "test",
		CIDpad: []byte{1, 2, 3, 4, 5, 6}, CIDkey: ckey, WriteAuth: wauth,
	}

	// UID counter
	vm := make(map[uint64]VMeta)
	var fCount uint64 = 0
	var fileCount uint64 = 1000000

	var walk func(depth int) VFile
	walk = func(depth int) VFile {
		// generate folder node
		fCount++
		uid := fCount
		var f VFile
		f.SetUID(uid)
		f.SetSL(SL_CONTROLLED)
		f.SetFlag(FLAG_DIR, true)
		name := "abcdefghabcdefghabcdefghabcdefgh"
		vm[uid] = VMeta{Name: name, EdTime: 12345678}
		if depth < 18 {
			f.Children = append(f.Children, walk(depth+1), walk(depth+1))
		} else {
			// add 10 files at the end node
			for i := 0; i < 10; i++ {
				fileCount++
				fuid := fileCount
				var child VFile
				child.SetUID(fuid)
				child.SetSL(SL_CONTROLLED)
				fname := "abcdefghabcdefghabcdefghabcdefgh"

				mask := Bencrypt.GetMasker(-1)
				key, _ := mask.XOR([]byte("abcdefghabcdefghabcdefghabcdefghabcdefghabcdefgh"))
				var key48 [48]byte
				copy(key48[:], key)
				vm[fuid] = VMeta{Name: fname, EdTime: 12345678, Size: 12345678, EncSize: 12345678, Key: key48}
				f.Children = append(f.Children, child)
			}
		}
		return f
	}

	root := walk(1)
	p := new(PEVFS)
	p.Init(vu, root, vm, SL_TOPSECRET, 48)
	return p
}

func countPEVFS(node VFile, folders *int, files *int) {
	if node.GetFlag(FLAG_DIR) {
		*folders++
	} else {
		*files++
	}
	for i := 0; i < len(node.Children); i++ {
		countPEVFS(node.Children[i], folders, files)
	}
}

func TestMain(m *testing.M) {
	// helper functions
	temp := []byte("qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM")
	res, err := Decompress(Compress(temp))
	fmt.Printf("Zstd: %t %v\n", bytes.Equal(temp, res), err)

	// PEVFS Pack Unpack
	pevfs := buildPEVFS()
	buf := new(bytes.Buffer)
	err = pevfs.Pack([]byte("hkey"), []byte("salt"), "msg", buf)
	if err == nil {
		fmt.Println("PEVFS Pack success")
	} else {
		fmt.Printf("PEVFS Pack %v\n", err)
	}
	temp = buf.Bytes()
	fmt.Printf("Packed Size %d\n", len(temp))

	msg, salt, err := pevfs.View(bytes.NewBuffer(temp))
	fmt.Printf("PEVFS View %t %t %v\n", msg == "msg", bytes.Equal(salt, []byte("salt")), err)
	err = pevfs.Unpack([]byte("hkey"), bytes.NewBuffer(temp))
	if err == nil {
		fmt.Println("PEVFS Unpack success")
	} else {
		fmt.Printf("PEVFS Unpack %v\n", err)
	}

	// check user integrity
	fmt.Printf("VUser: %t %t %t %t %t %t %t %t\n",
		pevfs.Account.StorageName == "test",
		pevfs.Account.UserName == "root",
		pevfs.Account.SecureLevel == SL_TOPSECRET,
		pevfs.Account.UserBitA == "test",
		pevfs.Account.UserBitB == "test",
		bytes.Equal(pevfs.Account.CIDpad, []byte{1, 2, 3, 4, 5, 6}),
		bytes.Equal(pevfs.Account.CIDkey, []byte("abcdefghabcdefghabcdefghabcdefgh")),
		bytes.Equal(pevfs.Account.WriteAuth, []byte("abcdefghabcdefghabcdefghabcdefgh")),
	)

	// check tree integrity
	var folders, files int
	countPEVFS(pevfs.Root, &folders, &files)
	fmt.Printf("Count: %d %d\n", folders, files)

	// folder metadata
	fMeta, fOk := pevfs.Meta[1]
	fmt.Printf("Folder Meta: %t %t %t\n", fOk, fMeta.Name == "abcdefghabcdefghabcdefghabcdefgh", fMeta.EdTime == 12345678)

	// file metadata
	key := []byte("abcdefghabcdefghabcdefghabcdefghabcdefghabcdefgh")
	fileMeta, fileOk := pevfs.Meta[1000001]
	mask := Bencrypt.GetMasker(-1)
	temp, _ = mask.XOR(fileMeta.Key[:])
	fmt.Printf("File Meta: %t %t %t %t %t %t\n",
		fileOk,
		fileMeta.Name == "abcdefghabcdefghabcdefghabcdefgh",
		fileMeta.EdTime == 12345678,
		fileMeta.Size == 12345678,
		fileMeta.EncSize == 12345678,
		bytes.Equal(temp, key[:]),
	)

	// bloom filter
	bf := new(BloomFilter)
	bf.Init(1000, 0.01)
	cid1 := pevfs.Account.GetCID(1, 0)
	cid2 := pevfs.Account.GetCID(1000001, 0)
	bf.Add(cid1)
	fmt.Printf("BloomFilter1: %t %t\n", bf.Test(cid1), bf.Test(cid2))

	temp = bf.Export()
	bf2 := new(BloomFilter)
	err = bf2.Import(temp)
	fmt.Printf("BloomFilter2: %t %t %v\n", bf2.Test(cid1), bf2.Test(cid2), err)

	// chunk balancer & virtual io
	units := make([]ChunkUnit, 4)
	units[0].Init("a", 1048576, 1.0)
	units[1].Init("b", 1048576, 1.5)
	units[2].Init("c", 1048576, 2.0)
	units[3].Init("d", 1048576, 2.5)
	cb := new(ChunkBalancer)
	cb.Init(".", units)

	// Account IO
	accBuf := bytes.NewBuffer([]byte("account_data"))
	err1 := cb.SetAccount("root", accBuf, int64(accBuf.Len()))
	resAcc := new(bytes.Buffer)
	err2 := cb.GetAccount("root", resAcc)
	fmt.Printf("Account IO: %t %v %v\n", bytes.Equal(resAcc.Bytes(), []byte("account_data")), err1, err2)

	// Write chunks
	cids := make([][]byte, 32)
	for i := 0; i < 32; i++ {
		cids[i] = pevfs.Account.GetCID(1000001, uint32(i))
		_ = cb.WriteChunk(cids[i], []byte(fmt.Sprintf("chunk_data_%d", i)))
	}

	// Check chunks
	allExist := true
	for i := 0; i < 32; i++ {
		ok, _ := cb.CheckChunk(cids[i], true)
		if !ok {
			allExist = false
		}
	}
	fmt.Printf("Chunk CRC32 Check: %t\n", allExist)

	// Read chunks
	readOk := true
	for i := 0; i < 32; i++ {
		dat, _ := cb.ReadChunk(cids[i])
		if !bytes.Equal(dat, []byte(fmt.Sprintf("chunk_data_%d", i))) {
			readOk = false
		}
	}
	fmt.Printf("Chunk Read: %t\n", readOk)

	// Delete chunks (8)
	delOk := true
	for i := 0; i < 8; i++ {
		err := cb.DelChunk(cids[i])
		ok, _ := cb.CheckChunk(cids[i], false)
		if err != nil || ok {
			delOk = false
		}
	}
	fmt.Printf("Chunk Delete: %t\n", delOk)

	// Trim chunks (16)
	bf3 := new(BloomFilter)
	bf3.Init(16, 0.01)
	for i := 16; i < 32; i++ {
		bf3.Add(cids[i])
	}
	trimmed, err := cb.TrimChunk(bf3.Export())
	trimOk := true
	for i := 8; i < 16; i++ {
		ok, _ := cb.CheckChunk(cids[i], false)
		if ok {
			trimOk = false
		}
	}
	fmt.Printf("Chunk Trim: %t %d %v\n", trimOk, trimmed, err)

	fdel, err := cb.TrimEmpty()
	fCount := 0
	for i := 0; i < 32; i++ {
		ok, _ := cb.CheckChunk(cids[i], false)
		if ok {
			fCount++
		}
	}
	fmt.Printf("Fdel %d, Fcount %d, %v\n", fdel, fCount, err)
}
