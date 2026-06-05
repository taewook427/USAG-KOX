// test817a : FalseCrypt PEVFS
package FalseCrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"runtime"
	"strings"
	"sync"

	"github.com/k-atusa/USAG-Lib/Bencrypt"
	"github.com/k-atusa/USAG-Lib/Icons"
	"github.com/k-atusa/USAG-Lib/Opsec"
	"github.com/k-atusa/USAG-Lib/Star"

	"github.com/klauspost/compress/zstd"
)

var SCLEAR_BACK = func(b []byte) { clear(b) }

func sclear(data []byte) { SCLEAR_BACK(data); runtime.KeepAlive(data) }

// Helpers
func Compress(data []byte) []byte {
	z, err := zstd.NewWriter(nil)
	if err != nil {
		return nil
	}
	defer z.Close()
	return z.EncodeAll(data, make([]byte, 0, len(data)/2))
}

func Decompress(data []byte) ([]byte, error) {
	z, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}
	defer z.Close()
	return z.DecodeAll(data, nil)
}

func SHA3256(data []byte) []byte {
	hash := sha3.Sum256(data)
	return hash[:]
}

func HMAC3256(key []byte, data []byte) []byte {
	h := hmac.New(func() hash.Hash { return sha3.New256() }, key)
	h.Write(data)
	return h.Sum(nil)
}

// Account Data
type VUser struct {
	StorageName string
	UserName    string // root: RW, else: R
	SecureLevel uint8
	UserBitA    string
	UserBitB    string

	CIDpad    []byte // 6B
	CIDkey    []byte // masked, 32B
	WriteAuth []byte // 32B
	mask      *Bencrypt.Masker
}

func (u *VUser) pack() ([]byte, error) {
	mp := make(map[string][]byte)
	mp["sname"] = []byte(u.StorageName)
	mp["uname"] = []byte(u.UserName)
	mp["slvl"] = []byte{u.SecureLevel}
	mp["ubita"] = []byte(u.UserBitA)
	mp["ubitb"] = []byte(u.UserBitB)

	mp["cpad"] = u.CIDpad
	ck, err := u.mask.XOR(u.CIDkey)
	defer sclear(ck)
	if err != nil {
		return nil, err
	}
	mp["ckey"] = ck
	mp["wauth"] = u.WriteAuth

	return Opsec.EncodeCfg(mp)
}

func (u *VUser) unpack(data []byte) error {
	mp := Opsec.DecodeCfg(data)
	u.StorageName = string(mp["sname"])
	u.UserName = string(mp["uname"])
	u.SecureLevel = uint8(mp["slvl"][0])
	u.UserBitA = string(mp["ubita"])
	u.UserBitB = string(mp["ubitb"])

	var err error = nil
	u.CIDpad = bytes.Clone(mp["cpad"])
	u.CIDkey, err = u.mask.XOR(mp["ckey"])
	if err != nil {
		return err
	}
	u.WriteAuth = bytes.Clone(mp["wauth"])
	return nil
}

func (u *VUser) GetCID(uid uint64, idx uint32) []byte {
	// get key and temp buffer
	key, err := u.mask.XOR(u.CIDkey)
	defer sclear(key)
	if err != nil {
		return nil
	}
	var temp [16]byte

	// 6B UID, 4B index, 6B padding
	var uidBuf [8]byte
	binary.LittleEndian.PutUint64(uidBuf[:], uid)
	copy(temp[0:6], uidBuf[:6])
	binary.LittleEndian.PutUint32(temp[6:10], idx)
	copy(temp[10:16], u.CIDpad)

	// in-place encrypt
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	block.Encrypt(temp[:], temp[:])
	return temp[:]
}

// Structure Data
const (
	FLAG_WORKING  uint8 = 7
	FLAG_DIR      uint8 = 6
	FLAG_EMPTY    uint8 = 5
	FLAG_COMPRESS uint8 = 4
	FLAG_SECURE_A uint8 = 3
	FLAG_SECURE_B uint8 = 2
	FLAG_USER_A   uint8 = 1
	FLAG_USER_B   uint8 = 0
)

const (
	SL_TOPSECRET    uint8 = 3
	SL_SECRET       uint8 = 2
	SL_CONFIDENTIAL uint8 = 1
	SL_CONTROLLED   uint8 = 0
)

type VFile struct {
	Data     [8]byte // 1B None, 1B Flags, 6B UID
	Children []VFile
}

func (f *VFile) GetFlag(tp uint8) bool {
	return ((f.Data[1] >> tp) & 1) == 1
}

func (f *VFile) SetFlag(tp uint8, val bool) {
	if val {
		f.Data[1] |= (1 << tp)
	} else {
		f.Data[1] &= ^(1 << tp)
	}
}

func (f *VFile) GetSL() uint8 {
	if f.GetFlag(FLAG_SECURE_A) {
		if f.GetFlag(FLAG_SECURE_B) {
			return SL_TOPSECRET
		} else {
			return SL_SECRET
		}
	} else {
		if f.GetFlag(FLAG_SECURE_B) {
			return SL_CONFIDENTIAL
		} else {
			return SL_CONTROLLED
		}
	}
}

func (f *VFile) SetSL(sl uint8) {
	switch sl {
	case SL_TOPSECRET:
		f.SetFlag(FLAG_SECURE_A, true)
		f.SetFlag(FLAG_SECURE_B, true)
	case SL_SECRET:
		f.SetFlag(FLAG_SECURE_A, true)
		f.SetFlag(FLAG_SECURE_B, false)
	case SL_CONFIDENTIAL:
		f.SetFlag(FLAG_SECURE_A, false)
		f.SetFlag(FLAG_SECURE_B, true)
	case SL_CONTROLLED:
		f.SetFlag(FLAG_SECURE_A, false)
		f.SetFlag(FLAG_SECURE_B, false)
	}
}

func (f *VFile) GetUID() uint64 {
	var uid uint64 = 0 // little endian
	for i := 7; i >= 2; i-- {
		uid <<= 8
		uid |= uint64(f.Data[i])
	}
	return uid
}

func (f *VFile) SetUID(uid uint64) {
	for i := 2; i <= 7; i++ {
		f.Data[i] = byte(uid)
		uid >>= 8
	}
}

// Metadata
type VMeta struct {
	Name   string
	EdTime uint64

	Key     [48]byte // masked
	Size    uint64
	EncSize uint64
}

// Personal Encryption Virtual File System
type PEVFS struct {
	Account VUser
	Root    VFile
	Meta    map[uint64]VMeta

	SecureLvl uint8
	Keylen    uint8
	Mask      *Bencrypt.Masker
}

func (p *PEVFS) Init(vu VUser, vf VFile, vm map[uint64]VMeta, sl uint8, kl uint8) {
	p.Account = vu
	p.Root = vf
	if vm == nil {
		vm = make(map[uint64]VMeta)
	} else {
		p.Meta = vm
	}
	p.SecureLvl = sl
	p.Keylen = kl
	p.Mask = Bencrypt.GetMasker(-1)
	p.Account.mask = p.Mask
}

func (p *PEVFS) View(src io.Reader) (string, []byte, error) {
	ops := new(Opsec.Opsec)
	ops.Reset()
	header, err := ops.Read(src, 0)
	if err != nil {
		return "", nil, err
	}
	ops.View(header) // get msg, salt
	return ops.Msg, ops.MsgInfo, nil
}

func (p *PEVFS) Pack(hkey []byte, salt []byte, msg string, dst io.Writer) error {
	// Initialize Star and lock
	tw := new(Star.TarWriter)
	if err := tw.Init(""); err != nil {
		return err
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var errU, errS, errM error
	wg.Add(3)

	// Pack and Write structure data
	go func() {
		defer wg.Done()
		defer func() {
			if e := recover(); e != nil {
				errS = fmt.Errorf("PackStruct panic: %v", e)
			}
		}()

		// pack structure data
		sBuf := bytes.NewBuffer(make([]byte, 0, 1048576))
		if err := p.packStruct(sBuf, p.Root, 0); err != nil {
			errS = err
			return
		}
		sDat := sBuf.Bytes()
		defer sclear(sDat)

		// write structure data
		mu.Lock()
		defer mu.Unlock()
		errS = tw.WriteBin("struct", sDat, 0644)
	}()

	// pack metadata
	go func() {
		defer wg.Done()
		defer func() {
			if e := recover(); e != nil {
				errM = fmt.Errorf("PackMeta panic: %v", e)
			}
		}()

		// pack metadata
		mBuf := bytes.NewBuffer(make([]byte, 0, 1048576))
		if err := p.packMeta(mBuf, p.Root); err != nil {
			errM = err
			return
		}
		mDat := mBuf.Bytes()
		defer sclear(mDat)

		// write metadata
		mu.Lock()
		defer mu.Unlock()
		errM = tw.WriteBin("meta", mDat, 0644)
	}()

	// pack user data
	go func() {
		defer wg.Done()
		defer func() {
			if e := recover(); e != nil {
				errU = fmt.Errorf("PackUser panic: %v", e)
			}
		}()

		// pack user data
		uDat, err := p.Account.pack()
		if err != nil {
			errU = err
			return
		}
		defer sclear(uDat)

		// write user data
		mu.Lock()
		defer mu.Unlock()
		errU = tw.WriteBin("user", uDat, 0644)
	}()

	// Wait and catch error
	wg.Wait()
	if errU != nil || errS != nil || errM != nil {
		temp, _ := tw.Close()
		sclear(temp)
		if errU != nil {
			return errU
		}
		if errS != nil {
			return errS
		}
		return errM
	}

	// 1. get tar1 packed body
	tarData, err := tw.Close()
	defer sclear(tarData)
	if err != nil {
		return err
	}

	// 2. Opsec header
	ops := new(Opsec.Opsec)
	defer func() { sclear(ops.BodyKey) }()
	ops.Reset()
	ops.Msg = msg
	ops.MsgInfo = salt

	sm := new(Bencrypt.SymMaster)
	defer func() { sclear(sm.Key) }()
	if err := sm.Init("gcmx1", make([]byte, 44)); err != nil {
		return err
	}

	ops.BodySize = sm.AfterSize(int64(len(tarData)))
	ops.BodyAlgo = "gcmx1"
	ops.BodyInfo = []byte("tar1")

	header, err := ops.Encpw("sha3", hkey, nil)
	if err != nil {
		return err
	}

	// 3. write webp and body
	var writed int64 = 0
	ico := Icons.ZipWebp
	prehead := append(ico, make([]byte, 128-len(ico)%128)...)
	writed += int64(len(prehead))
	if _, err := dst.Write(prehead); err != nil {
		return err
	}

	writed += int64(len(header)) + 6
	if len(header) >= 65535 {
		writed += 2
	}
	if err := ops.Write(dst, header); err != nil {
		return err
	}

	if err := sm.Init("gcmx1", ops.BodyKey); err != nil {
		return err
	}
	if err := sm.EnFile(bytes.NewReader(tarData), int64(len(tarData)), dst); err != nil {
		return err
	}
	writed += ops.BodySize

	// 4. padding
	padLen := Opsec.PadLen(writed)
	if padLen > 0 {
		if err := Opsec.PadFile(dst, padLen); err != nil {
			return err
		}
	}
	return nil
}

func (p *PEVFS) packStruct(buf *bytes.Buffer, node VFile, depth uint8) error {
	// check Secure Level
	if node.GetSL() > p.SecureLvl {
		return nil
	}

	// 1B depth, 1B flags, 6B UID
	node.Data[0] = depth
	buf.Write(node.Data[:])
	node.Data[0] = 0
	if depth == 255 && len(node.Children) > 0 {
		return errors.New("File tree exceeds maximum depth")
	}

	// write children
	for i := 0; i < len(node.Children); i++ {
		if err := p.packStruct(buf, node.Children[i], depth+1); err != nil {
			return err
		}
	}
	return nil
}

func (p *PEVFS) packMeta(buf *bytes.Buffer, node VFile) error {
	// check Secure Level
	if node.GetSL() > p.SecureLvl {
		return nil
	}

	// find metadata
	var temp [8]byte
	meta, ok := p.Meta[node.GetUID()]
	if !ok {
		return errors.New("Cannot find file node metadata")
	}

	buf.Write(node.Data[2:8]) // 6B UID
	if strings.ContainsRune(meta.Name, 0) {
		return errors.New("Null byte in file name")
	}
	buf.Write([]byte(meta.Name))
	buf.WriteByte(0) // C-style string name
	binary.LittleEndian.PutUint64(temp[:], meta.EdTime)
	buf.Write(temp[:]) // 8B EdTime

	if node.GetFlag(FLAG_DIR) || node.GetFlag(FLAG_EMPTY) {
		buf.WriteByte(0) // pass when directory or empty
	} else {
		buf.WriteByte(p.Keylen) // 1B keylen
		key, err := p.Mask.XOR(meta.Key[0:p.Keylen])
		if err != nil {
			return err
		}
		buf.Write(key) // unmasked key
		sclear(key)
		binary.LittleEndian.PutUint64(temp[:], meta.Size)
		buf.Write(temp[:]) // 8B Size
		binary.LittleEndian.PutUint64(temp[:], meta.EncSize)
		buf.Write(temp[:]) // 8B EncSize
	}

	// write children
	for i := 0; i < len(node.Children); i++ {
		if err := p.packMeta(buf, node.Children[i]); err != nil {
			return err
		}
	}
	return nil
}

func (p *PEVFS) Unpack(hkey []byte, src io.Reader) error {
	// 1. Opsec header read and decrypt
	ops := new(Opsec.Opsec)
	defer func() { sclear(ops.BodyKey) }()
	ops.Reset()

	header, err := ops.Read(src, 0)
	if err != nil {
		return err
	}
	ops.View(header)
	if err := ops.Decpw(hkey, nil); err != nil {
		return err
	}

	// 2. Decrypt body (tar1 data)
	sm := new(Bencrypt.SymMaster)
	defer func() { sclear(sm.Key) }()
	if err := sm.Init(ops.BodyAlgo, ops.BodyKey); err != nil {
		return err
	}
	tBuf := bytes.NewBuffer(make([]byte, 0, ops.BodySize))
	if err := sm.DeFile(src, ops.BodySize, tBuf); err != nil {
		return err
	}
	tarData := tBuf.Bytes()

	// 3. Read tar sequentially and extract components
	tr := new(Star.TarReader)
	if err := tr.Init(tarData); err != nil {
		sclear(tarData)
		return err
	}

	var userDat, structDat, metaDat []byte
	for tr.Next() {
		if !tr.IsDir {
			switch tr.Name {
			case "user":
				userDat = tr.Read()
			case "struct":
				structDat = tr.Read()
			case "meta":
				metaDat = tr.Read()
			}
		}
	}
	tr.Close()
	sclear(tarData)

	// 4. Unpack components in parallel
	var wg sync.WaitGroup
	var errU, errS, errM error
	wg.Add(3)

	// unpack structure data
	go func() {
		defer wg.Done()
		defer func() {
			if e := recover(); e != nil {
				errS = fmt.Errorf("UnpackStruct panic: %v", e)
			}
		}()

		if structDat != nil {
			defer sclear(structDat)
			_, root, err := p.unpackStruct(structDat, 0, len(structDat), 0)
			if err != nil {
				errS = err
				return
			}
			p.Root = root
		}
	}()

	// unpack metadata
	go func() {
		defer wg.Done()
		defer func() {
			if e := recover(); e != nil {
				errM = fmt.Errorf("UnpackMeta panic: %v", e)
			}
		}()

		if metaDat != nil {
			defer sclear(metaDat)
			p.Meta = make(map[uint64]VMeta)
			if err := p.unpackMeta(metaDat); err != nil {
				errM = err
				return
			}
		}
	}()

	// unpack user data
	go func() {
		defer wg.Done()
		defer func() {
			if e := recover(); e != nil {
				errU = fmt.Errorf("UnpackUser panic: %v", e)
			}
		}()

		if userDat != nil {
			defer sclear(userDat)
			if err := p.Account.unpack(userDat); err != nil {
				errU = err
				return
			}
		}
	}()

	// Wait and catch error
	wg.Wait()
	if errU != nil || errS != nil || errM != nil {
		if errU != nil {
			return errU
		}
		if errS != nil {
			return errS
		}
		return errM
	}
	return nil
}

func (p *PEVFS) unpackStruct(full []byte, st int, ed int, curdepth uint8) (int, VFile, error) {
	// check validity
	if st+8 > ed {
		return st, VFile{}, errors.New("Unexpected end of structure data")
	}
	if full[st] != curdepth {
		return st, VFile{}, errors.New("Invalid structure depth sequence")
	}

	// get current node
	var node VFile
	copy(node.Data[:], full[st:st+8])
	node.Data[0] = 0
	st += 8

	// recursion while there are children
	for st < ed && full[st] == curdepth+1 {
		nextSt, child, err := p.unpackStruct(full, st, ed, curdepth+1)
		if err != nil {
			return st, VFile{}, err
		}
		node.Children = append(node.Children, child)
		st = nextSt
	}
	return st, node, nil
}

func (p *PEVFS) unpackMeta(data []byte) error {
	reader := bytes.NewReader(data)
	for reader.Len() > 0 {
		var meta VMeta

		// 1. 6B UID
		var uidBuf [8]byte
		if _, err := reader.Read(uidBuf[0:6]); err != nil {
			return err
		}
		uid := binary.LittleEndian.Uint64(uidBuf[:])

		// 2. C-Style name
		var nameBuf bytes.Buffer
		for {
			b, err := reader.ReadByte()
			if err != nil {
				return err
			}
			if b == 0 {
				break
			}
			nameBuf.WriteByte(b)
		}
		meta.Name = nameBuf.String()

		// 3. 8B EdTime
		if err := binary.Read(reader, binary.LittleEndian, &meta.EdTime); err != nil {
			return err
		}

		// 4. 1B keylen
		keyLen, err := reader.ReadByte()
		if err != nil {
			return err
		}
		if keyLen > 0 {
			// 5. read key and mask
			unmaskedKey := make([]byte, keyLen)
			if _, err := reader.Read(unmaskedKey); err != nil {
				return err
			}
			maskedKey, err := p.Mask.XOR(unmaskedKey)
			sclear(unmaskedKey)
			if err != nil {
				return err
			}
			copy(meta.Key[:], maskedKey)

			// 6. 8B Size, 8B EncSize
			if err := binary.Read(reader, binary.LittleEndian, &meta.Size); err != nil {
				return err
			}
			if err := binary.Read(reader, binary.LittleEndian, &meta.EncSize); err != nil {
				return err
			}
		}
		p.Meta[uid] = meta
	}
	return nil
}
