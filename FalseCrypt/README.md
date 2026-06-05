## FalseCrypt

USAG-Lib과 호환 기술을 사용한 개인 암호화 가상 파일 시스템 핵심 기능들

Core functions of personal encrypted virtual file system based on USAG-Lib and compatiable technologies

#### Golang

```golang
func Compress(data []byte) []byte
func Decompress(data []byte) ([]byte, error)
func SHA3256(data []byte) []byte
func HMAC3256(key []byte, data []byte) []byte

FLAG_WORKING uint8
FLAG_DIR uint8
FLAG_EMPTY uint8
FLAG_COMPRESS uint8
FLAG_USER_A uint8
FLAG_USER_B uint8

SL_TOPSECRET uint8
SL_SECRET uint8
SL_CONFIDENTIAL uint8
SL_CONTROLLED uint8

struct VUser {
    StorageName string
    UserName    string
    SecureLevel uint8
    UserBitA    string
    UserBitB    string

    CIDpad    []byte
    CIDkey    []byte // masked
    WriteAuth []byte

    func GetCID(uid uint64, idx uint32) []byte
}

struct VFile {
    Data     [8]byte
    Children []VFile

    func GetFlag(tp uint8) bool
    func SetFlag(tp uint8, val bool)
    func GetSL() uint8
    func SetSL(sl uint8)
    func GetUID() uint64
    func SetUID(uid uint64)
}

struct VMeta {
    Name   string
    EdTime uint64

    Key     [48]byte // masked
    Size    uint64
    EncSize uint64
}

struct PEVFS {
    func Init(vu VUser, vf VFile, vm map[uint64]VMeta, sl uint8, kl uint8)
    func View(src io.Reader) (string, []byte, error)
    func Pack(hkey []byte, salt []byte, msg string, dst io.Writer) error
    func Unpack(hkey []byte, src io.Reader) error
}

struct BloomFilter {
    func Init(cidNum uint64, fpRate float64)
    func Import(data []byte) error
    func Export() []byte
    func Add(cid []byte)
    func Test(cid []byte) bool
}

interface VirtualIO {
    func GetAccount(username string, dst io.Writer) error
    func SetAccount(username string, src io.Reader, size int64) error

    func ReadChunk(cid []byte) ([]byte, error)
    func WriteChunk(cid []byte, data []byte) error
    func DelChunk(cid []byte) error
    func CheckChunk(cid []byte, chkHash bool) (bool, error)
    func TrimChunk(bloom []byte) (int, error)
}

struct ChunkUnit {
    func Init(path string, cap int64, weight float32)
}

struct ChunkBalancer(VirtualIO) {
    func Init(mainPath string, units []ChunkUnit)
    func TrimEmpty() (int, error)
}
```

#### Java

```java
byte[] Compress(byte[] data)
byte[] Decompress(byte[] data)
byte[] SHA3256(byte[] data)
byte[] HMAC3256(byte[] key, byte[] data)

byte FLAG_WORKING
byte FLAG_DIR
byte FLAG_EMPTY
byte FLAG_COMPRESS
byte FLAG_USER_A
byte FLAG_USER_B

byte SL_TOPSECRET
byte SL_SECRET
byte SL_CONFIDENTIAL
byte SL_CONTROLLED

class VUser {
    String StorageName
    String UserName
    byte SecureLevel
    String UserBitA
    String UserBitB

    byte[] CIDpad
    byte[] CIDkey // masked
    byte[] WriteAuth

    byte[] GetCID(long uid, int idx)
}

class VFile {
    byte[] Data // byte[8]
    List<VFile> Children

    boolean GetFlag(byte tp)
    void SetFlag(byte tp, boolean val)
    byte GetSL()
    void SetSL(byte sl)
    long GetUID()
    void SetUID(long uid)
}

class VMeta {
    String Name
    long EdTime

    byte[] Key // byte[48], masked
    long Size
    long EncSize
}

class PEVFS {
    void Init(VUser vu, VFile vf, Map<Long, VMeta> vm, byte sl, byte kl)
    ViewResult View(InputStream src)
    void Pack(byte[] hkey, byte[] salt, String msg, OutputStream dst)
    void Unpack(byte[] hkey, InputStream src)

    class ViewResult {
        String Msg
        byte[] Salt
    }
}

abstract class VirtualIO {
    void GetAccount(String username, OutputStream dst)
    void SetAccount(String username, InputStream src, long size)
    byte[] ReadChunk(byte[] cid)
    void WriteChunk(byte[] cid, byte[] data)
    void DelChunk(byte[] cid)
}
```

#### PEVFS

- 모든 암호화 연산은 클라이언트에서 처리한다.
- 저장소는 로컬 폴더들 혹은 원격 HTTP 서버를 지정하며, 계정 파일과 데이터 청크의 단순 입출력을 처리한다.
- 특정 폴더만을 포함하는 계정을 생성하여 공유할 수 있으며, 쓰기 권한 키를 제외하여 읽기전용으로 만든다.
- 암호화된 파일은 일정 단위로 잘려 데이터 청크로 저장되며, `[6B UID][4B 청크순서][6B 패딩]`을 암호화해 청크 ID로 사용한다.

- 계정 파일
    - 계정데이터
        - 저장소명(불변)
        - 사용자명(불변): root만 쓰기 권한을 가지며 나머지는 읽기전용
        - 권한 레벨(불변)
        - 사용자 비트 설정값
        - 청크명 키(불변)
        - 쓰기 권한 키
    - 구조데이터
        - `[1B 깊이][1B 플래그][6B UID]`의 연속
        - 최대 폴더 깊이 255단계
        - 파일과 폴더마다 고유한 UID 부여
        - 점진적 작업기록 지원
        - 플래그: 작업기록, 폴더, 빈파일, zstd압축, 보안레벨(2), 사용자설정(2)
    - 메타데이터
        - 이름, 수정시각, 크기, 데이터 키 등
        - 폴더나 빈 파일은 데이터 키와 크기를 기록하지 않음
        - 6B UID: 파일/폴더 고유주소
        - Name: C-style로 0으로 끝나게 저장
        - 8B EdTime: 마지막 수정시각
        - 1B Keylen: 데이터 키 길이, 없다면 0
        - key: 실제 데이터 암호화 키
        - 8B Size: 원본 크기
        - 8B EncSize: 암호화와 패딩 후 크기

- All encryption operations are handled on the client side.
- The storage specifies local folders or a remote HTTP server and handles simple I/O for account files and data chunks.
- You can create and share accounts containing only specific folders, and make them read-only by excluding the write permission key.
- Encrypted files are split into fixed units and stored as data chunks, using `[6B UID][4B Chunk Order][6B Padding]` encrypted as the chunk ID.

- Account File
    - Account Data
        - Storage Name (Immutable)
        - Username (Immutable): Only root has write permissions, others are read-only
        - Permission Level (Immutable)
        - User Bit Setting
        - Chunk Name Key (Immutable)
        - Write Permission Key
    - Structure Data
        - Consecutive `[1B Depth][1B Flags][6B UID]`
        - Maximum folder depth 255 levels
        - Unique UID assigned to each file and folder
        - Supports incremental history
        - Flags: History, Folder, Empty File, zstd compression, Security Level (2), Custom (2)
    - Metadata
        - Name, Modification Time, Size, Data Key, etc
        - Folders or empty files do not record data key and size
        - 6B UID: Unique file/folder address
        - Name: Stored in C-style ending with 0
        - 8B EdTime: Last Modified Time
        - 1B Keylen: Data key length; 0 if null
        - key: Actual data encryption key
        - 8B Size: Original Size
        - 8B EncSize: Size after encryption and padding

- Algorithm: arg2-sha3, gcmx1, tar1
- Normal Usage: 20k Folders + 200k Files
- Practical Limit: 4m Folders + 40m Files
