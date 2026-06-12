// test817b : FalseCrypt IO
package FalseCrypt

import (
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Bloom Filter to check CID exists
type BloomFilter struct {
	filterSize uint64
	hashCount  uint32
	data       []byte
}

func (bf *BloomFilter) Init(cidNum uint64, fpRate float64) {
	// get filter size, -(num * ln(fpRate)) / (ln(2)^2)
	if cidNum == 0 {
		cidNum = 1
	}
	if fpRate <= 0 || fpRate >= 1 {
		fpRate = 0.01
	}
	bf.filterSize = uint64(math.Ceil(-float64(cidNum) * math.Log(fpRate) / math.Pow(math.Log(2), 2)))
	if bf.filterSize%8 != 0 {
		bf.filterSize += 8 - (bf.filterSize % 8)
	}

	// get hash count, (filterSize / num) * ln(2)
	bf.hashCount = uint32(math.Round(float64(bf.filterSize) / float64(cidNum) * math.Log(2)))
	if bf.hashCount == 0 {
		bf.hashCount = 1
	}

	bf.data = make([]byte, bf.filterSize/8)
}

func (bf *BloomFilter) Import(data []byte) error {
	if len(data) < 12 {
		return errors.New("data too short")
	}
	bf.filterSize = binary.LittleEndian.Uint64(data[0:8])
	bf.hashCount = binary.LittleEndian.Uint32(data[8:12])
	bf.data = data[12:]
	if bf.filterSize%8 != 0 || len(bf.data) != int(bf.filterSize/8) {
		return errors.New("bloom filter data is corrupted")
	}
	return nil
}

func (bf *BloomFilter) Export() []byte {
	res := make([]byte, 12+len(bf.data))
	binary.LittleEndian.PutUint64(res[0:8], bf.filterSize)
	binary.LittleEndian.PutUint32(res[8:12], bf.hashCount)
	copy(res[12:], bf.data)
	return res
}

func (bf *BloomFilter) Add(cid []byte) {
	// CID is random 16B
	if len(cid) != 16 {
		return
	}
	g1 := binary.LittleEndian.Uint64(cid[0:8])
	g2 := binary.LittleEndian.Uint64(cid[8:16])

	// bit_pos = (g1 + i * g2) % filter_size
	for i := uint32(0); i < bf.hashCount; i++ {
		idx := (g1 + uint64(i)*g2) % bf.filterSize
		bf.data[idx/8] |= (1 << (idx % 8))
	}
}

func (bf *BloomFilter) Test(cid []byte) bool {
	// CID is random 16B
	if len(cid) != 16 {
		return false
	}
	g1 := binary.LittleEndian.Uint64(cid[0:8])
	g2 := binary.LittleEndian.Uint64(cid[8:16])

	// bit_pos = (g1 + i * g2) % filter_size
	for i := uint32(0); i < bf.hashCount; i++ {
		idx := (g1 + uint64(i)*g2) % bf.filterSize
		if (bf.data[idx/8] & (1 << (idx % 8))) == 0 {
			return false
		}
	}
	return true // can be false-positive
}

// IO interface
type VirtualIO interface {
	GetAccount(username string, dst io.Writer) error
	SetAccount(username string, src io.Reader, size int64) error

	ReadChunk(cid []byte) ([]byte, error)
	WriteChunk(cid []byte, data []byte) error
	DelChunk(cid []byte) error
	CheckChunk(cid []byte, chkHash bool) (bool, error)
	TrimChunk(bloom []byte) (int, error)
}

// Multi-folder chunk IO
func b32(d []byte) string {
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(d))
}

type ChunkUnit struct {
	Path   string
	Used   int64
	Cap    int64
	Weight float32
	lock   sync.RWMutex
}

func (cu *ChunkUnit) Init(path string, cap int64, weight float32) {
	cu.Path = path
	cu.Cap = cap
	cu.Weight = weight
	os.MkdirAll(path, 0755)

	// get used size of folder
	cu.Used = 0
	filepath.WalkDir(path, func(path string, e os.DirEntry, err error) error {
		if err == nil && !e.IsDir() {
			if info, err := e.Info(); err == nil {
				cu.Used += info.Size()
			}
		}
		return nil
	})
}

func (u *ChunkUnit) removeChunk(subDir string, filePrefix string) (bool, error) {
	targetDir := filepath.Join(u.Path, subDir)
	entries, err := os.ReadDir(targetDir)
	if err != nil {
		return false, nil // upper folder not exists
	}

	for _, entry := range entries {
		filename := entry.Name()
		if !entry.IsDir() && strings.HasPrefix(strings.ToLower(filename), filePrefix) {
			// get file size, remove physical file
			info, errI := entry.Info()
			var size int64
			if errI == nil {
				size = info.Size()
			}
			if err := os.Remove(filepath.Join(targetDir, filename)); err != nil {
				return false, err
			}

			// decrement used
			u.lock.Lock()
			u.Used -= size
			if u.Used < 0 {
				u.Used = 0
			}
			u.lock.Unlock()
			return true, nil // success
		}
	}
	return false, nil // not found
}

func (u *ChunkUnit) trimUnit(bf *BloomFilter, logErr func(string, error)) int64 {
	var deleted int64
	filepath.WalkDir(u.Path, func(path string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return nil
		}

		filename := e.Name() // standard filename is 30 chars
		if len(filename) == 30 {
			// get CID from filename
			d3 := filepath.Base(filepath.Dir(path))
			d2 := filepath.Base(filepath.Dir(filepath.Dir(path)))
			d1 := filepath.Base(filepath.Dir(filepath.Dir(filepath.Dir(path))))
			pBytes, errP := hex.DecodeString(d1 + d2 + d3)
			sBytes, errS := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(filename[:21]))

			// check CID is in Bloom Filter
			if errP == nil && errS == nil {
				cid := append(pBytes, sBytes...)
				if !bf.Test(cid) {

					// get file size
					info, errI := e.Info()
					var size int64
					if errI == nil {
						size = info.Size()
					}

					if errDel := os.Remove(path); errDel == nil {
						deleted++

						// decrement used
						u.lock.Lock()
						u.Used -= size
						if u.Used < 0 {
							u.Used = 0
						}
						u.lock.Unlock()
					} else {
						logErr(fmt.Sprintf("TrimChunk %s", path), errDel)
					}
				}
			}
		}
		return nil
	})
	return deleted
}

func (u *ChunkUnit) trimEmpty() (int, error) {
	var count int
	var walk func(string) error
	walk = func(path string) error {
		// check if path is a directory
		st, err := os.Stat(path)
		if err != nil {
			return err
		}
		if !st.IsDir() {
			return nil
		}

		// walk for all subfolders
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := walk(filepath.Join(path, e.Name())); err != nil {
				return err
			}
		}

		// check if folder is empty
		entries, err = os.ReadDir(path)
		if err != nil {
			return err
		}
		if len(entries) == 0 && path != u.Path {
			if err := os.Remove(path); err != nil {
				return err
			}
			count++
		}
		return nil
	}
	err := walk(u.Path)
	return count, err
}

type ChunkBalancer struct {
	MainPath string
	Units    []ChunkUnit
	lock     sync.RWMutex

	logLock     sync.Mutex
	logFile     *os.File
	logLastTime time.Time
	logClearEn  bool
}

func (cb *ChunkBalancer) Init(mainPath string, units []ChunkUnit) {
	cb.MainPath = mainPath
	cb.Units = units
	os.MkdirAll(mainPath, 0755)
}

func (cb *ChunkBalancer) GetAccount(username string, dst io.Writer) error {
	srcPath := filepath.Join(cb.MainPath, b32([]byte(username))+".webp")
	file, err := os.Open(srcPath)
	if err != nil {
		cb.logErr("GetAccount "+username, err)
		return err
	}
	defer file.Close()
	_, err = io.Copy(dst, file)
	if err != nil {
		cb.logErr("GetAccount "+username, err)
	}
	return err
}

func (cb *ChunkBalancer) SetAccount(username string, src io.Reader, size int64) error {
	dstPath := filepath.Join(cb.MainPath, b32([]byte(username))+".webp")
	file, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		cb.logErr("SetAccount "+username, err)
		return err
	}
	defer file.Close()
	_, err = io.Copy(file, io.LimitReader(src, size))
	if err != nil {
		cb.logErr("SetAccount "+username, err)
	}
	return err
}

func (cb *ChunkBalancer) ReadChunk(cid []byte) ([]byte, error) {
	h := hex.EncodeToString(cid[0:3])
	subDir := filepath.Join(h[0:2], h[2:4], h[4:6])
	filePrefix := b32(cid[3:]) + "_"

	// search by order
	for _, idx := range cb.getUnitsOrd(cid) {
		targetDir := filepath.Join(cb.Units[idx].Path, subDir)
		entries, err := os.ReadDir(targetDir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			filename := entry.Name()
			if !entry.IsDir() && strings.HasPrefix(strings.ToLower(filename), filePrefix) {

				// read physical file
				data, err := os.ReadFile(filepath.Join(targetDir, filename))
				if err != nil {
					cb.logErr(fmt.Sprintf("ReadChunk %x", cid), err)
					return nil, err
				}
				return data, nil
			}
		}
	}

	// not found
	err := errors.New("chunk not found")
	cb.logErr(fmt.Sprintf("ReadChunk %x", cid), err)
	return nil, err
}

func (cb *ChunkBalancer) WriteChunk(cid []byte, data []byte) error {
	// remove existing chunk
	cb.removeChunk(cid)

	ord := cb.getUnitsOrd(cid)
	checksum := crc32.ChecksumIEEE(data)
	size := int64(len(data))

	h := hex.EncodeToString(cid[:3])
	subDir := filepath.Join(h[0:2], h[2:4], h[4:6])
	newFileName := fmt.Sprintf("%s_%08x", b32(cid[3:]), checksum)

	// check capacity left by order
	for _, idx := range ord {
		cb.Units[idx].lock.Lock()
		if cb.Units[idx].Used+size <= cb.Units[idx].Cap {
			targetDir := filepath.Join(cb.Units[idx].Path, subDir)
			os.MkdirAll(targetDir, 0755)

			// write file, increment used
			err := os.WriteFile(filepath.Join(targetDir, newFileName), data, 0644)
			if err == nil {
				cb.Units[idx].Used += size
				cb.Units[idx].lock.Unlock()
				return nil
			} else {
				cb.logErr(fmt.Sprintf("WriteChunk %x", cid), err)
			}
		}
		cb.Units[idx].lock.Unlock()
	}
	err := errors.New("All storage units are full")
	cb.logErr(fmt.Sprintf("WriteChunk %x", cid), err)
	return err
}

func (cb *ChunkBalancer) DelChunk(cid []byte) error {
	err := cb.removeChunk(cid)
	if err != nil {
		cb.logErr(fmt.Sprintf("DelChunk %x", cid), err)
	}
	return err
}

func (cb *ChunkBalancer) CheckChunk(cid []byte, chkHash bool) (bool, error) {
	h := hex.EncodeToString(cid[0:3])
	subDir := filepath.Join(h[0:2], h[2:4], h[4:6])
	filePrefix := b32(cid[3:]) + "_"

	// search by order
	for _, idx := range cb.getUnitsOrd(cid) {
		targetDir := filepath.Join(cb.Units[idx].Path, subDir)
		entries, err := os.ReadDir(targetDir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			filename := entry.Name()
			if !entry.IsDir() && strings.HasPrefix(strings.ToLower(filename), filePrefix) {
				// check file existence
				if !chkHash {
					return true, nil
				}

				// check CRC32
				if len(filename) == 30 {
					// get crc value
					crcHex := filename[22:30]
					storedCRC, err := strconv.ParseUint(crcHex, 16, 32)
					if err != nil {
						continue
					}

					// read physical file
					data, err := os.ReadFile(filepath.Join(targetDir, filename))
					if err != nil {
						cb.logErr(fmt.Sprintf("CheckChunk %x", cid), err)
						return false, err
					}

					// compare CRC
					if crc32.ChecksumIEEE(data) != uint32(storedCRC) {
						errCorrupt := fmt.Errorf("CRC32 mismatch: %s/%s", targetDir, filename)
						cb.logErr(fmt.Sprintf("CheckChunk %x", cid), errCorrupt)
						return false, errCorrupt
					}
					return true, nil
				}
			}
		}
	}
	return false, nil // file not exists
}

func (cb *ChunkBalancer) TrimChunk(bloom []byte) (int, error) {
	// load bloom filter
	bf := new(BloomFilter)
	if err := bf.Import(bloom); err != nil {
		cb.logErr("TrimChunk BloomFilter", err)
		return 0, err
	}
	var wg sync.WaitGroup
	var totalDeleted int64

	// trim for each unit
	for i := range cb.Units {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					cb.logErr("TrimChunk panic", fmt.Errorf("%v", r))
				}
			}()
			localDeleted := cb.Units[idx].trimUnit(bf, cb.logErr)
			atomic.AddInt64(&totalDeleted, localDeleted)
		}(i)
	}
	wg.Wait()
	return int(totalDeleted), nil
}

func (cb *ChunkBalancer) TrimEmpty() (int, error) {
	var wg sync.WaitGroup
	var total int64 = 0
	var err error = nil

	for i := range cb.Units {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					cb.logErr("TrimEmpty panic", fmt.Errorf("%v", r))
				}
			}()
			count, terr := cb.Units[idx].trimEmpty()
			atomic.AddInt64(&total, int64(count))
			if terr != nil {
				cb.logErr("TrimEmpty "+cb.Units[idx].Path, terr)
				err = terr
			}
		}(i)
	}
	wg.Wait()
	return int(total), err
}

func (cb *ChunkBalancer) logErr(op string, err error) {
	if err == nil {
		return
	}
	cb.logLock.Lock()
	defer cb.logLock.Unlock()

	// open log file if not exists
	if cb.logFile == nil {
		logPath := filepath.Join(cb.MainPath, "log.txt")
		f, oErr := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if oErr != nil {
			return
		}
		cb.logFile = f
	}

	// write log and start cleaner if not enabled
	cb.logLastTime = time.Now()
	fmt.Fprintf(cb.logFile, "[%s] [%s] %v\n", cb.logLastTime.Format("2006-01-02 15:04:05"), op, err)
	if !cb.logClearEn {
		cb.logClearEn = true
		go func() {
			timeout := 5 * time.Minute
			for {
				time.Sleep(timeout) // sleep for a while
				cb.logLock.Lock()
				if time.Since(cb.logLastTime) >= timeout { // check last log time
					if cb.logFile != nil {
						cb.logFile.Close()
						cb.logFile = nil
					}
					cb.logClearEn = false
					cb.logLock.Unlock()
					return
				}
				cb.logLock.Unlock()
			}
		}()
	}
}

func (cb *ChunkBalancer) getUnitsOrd(cid []byte) []int {
	cb.lock.RLock()
	defer cb.lock.RUnlock()
	n := len(cb.Units)
	res := make([]int, n)
	scores := make([]float64, n)

	// CID is 16B random
	g1 := binary.LittleEndian.Uint64(cid[0:8])
	g2 := binary.LittleEndian.Uint64(cid[8:16])

	for i := 0; i < n; i++ {
		res[i] = i

		// SplitMix64
		mix := g1 ^ g2 ^ uint64(i)
		mix ^= mix >> 30
		mix *= 0xbf58476d1ce4e5b9
		mix ^= mix >> 27
		mix *= 0x94d049bb133111eb
		mix ^= mix >> 31

		// 0.0 ~ 1.0 Normalization
		norm := float64(mix) / float64(^uint64(0))
		scores[i] = norm * float64(cb.Units[i].Cap) * float64(cb.Units[i].Weight)
	}

	// sort by score
	sort.Slice(res, func(i, j int) bool {
		return scores[res[i]] > scores[res[j]]
	})
	return res
}

func (cb *ChunkBalancer) removeChunk(cid []byte) error {
	h := hex.EncodeToString(cid[0:3])
	subDir := filepath.Join(h[0:2], h[2:4], h[4:6])
	filePrefix := b32(cid[3:]) + "_"

	// search by order
	for _, idx := range cb.getUnitsOrd(cid) {
		found, err := cb.Units[idx].removeChunk(subDir, filePrefix)
		if err != nil {
			return err
		}
		if found {
			return nil
		}
	}
	return errors.New("chunk not found")
}
