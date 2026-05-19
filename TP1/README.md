## TP1

근거리 네트워크에서 데이터나 zip 파일을 종단간 암호화로 전송하는 프로토콜

A protocol for end-to-end encrypted transfer of data or ZIP files over a local area network

#### Golang

```go
MODE_MSGONLY uint16

HASH_SHA3 uint16
HASH_PBK2 uint16
HASH_ARG2 uint16

SYM_GCM1  uint16
SYM_GCMX1 uint16

ASYM_RSA1 uint16
ASYM_RSA2 uint16
ASYM_ECC1 uint16
ASYM_PQC1 uint16

STAGE_IDLE         int
STAGE_HANDSHAKE    int
STAGE_ENCRYPTING   int
STAGE_TRANSFERRING int
STAGE_COMPLETE     int
STAGE_ERROR        int

func GetIPs(v4only bool) ([]string, error)
func GetPath() string
func CleanPath(path string) string
func TempPath() string
func DelPath(path string) error

struct TP1 {
	Mode    uint16
	InMem   bool
	DoPad   bool
	SharedS []byte // masked

    func Init(mode uint16, inMem bool, doPad bool, secret []byte, conn net.Conn)
    func GetStatus() (int, uint64, uint64)
    func Send(src io.Reader, size int64, smsg string) ([]byte, []byte, error) // public key of (from, to)
    func Receive(dst io.Writer) ([]byte, []byte, string, error) // public key of (from, to)
}

struct TCPsocket {
	Listener net.Listener
	Conn     net.Conn

    func MakeListener(port string) error // for receiver
    func MakeConnection(addr string) error // for sender
    Close()
}
```

#### Protocol

- 수신자가 포트를 엽니다. The receiver opens a port.
- 송신자가 포트를 열고 TCP 소켓을 연결합니다. The sender opens a port and establishes a TCP socket connection.
- 송신자가 통신개시 패킷(매직 4B, 모드 2B)을 보냅니다. The sender transmits a communication initialization packet (Magic 4B, Mode 2B).
- 송신자와 수신자가 키 교환을 수행하여 핸드쉐이크합니다. 이때 사전에 공유된 암구호 S가 사용될 수 있습니다. The sender and receiver perform a handshake by executing a key exchange. A pre-shared passphrase S may be used.
    - 전송 순서 Transmission Order: 송신자 인증 -> 수신자 인증 -> 송신자 공개키 -> 수신자 공개키 Sender Authentication -> Receiver Authentication -> Sender Public Key -> Receiver Public Key
    - 인증 패킷 Authentication Packet: (논스 8B, 해시 32B), 해시 대상: 논스 + 공개키 + S (Nonce 8B, Hash 32B), Hash Target: Nonce + Public Key + S
    - 공개키 패킷 Public Key Packet: (길이 2B, 공개키) (Length 2B, Public Key)
- 수신자가 공개키를 만들고 통신개시 패킷(공개키길이 2B, 공개키)을 전송합니다. The receiver generates its own public key and transmits a communication initialization packet (Public Key Length 2B, Public Key).
- 송신자가 수신자의 공개키로 내용을 암호화하고 서명합니다. 동시에 하트비트 패킷(8B, 0은 진행 중, 최댓값은 오류 발생)을 보냅니다. The sender encrypts and signs the content using the receiver's public key. Simultaneously, it sends heartbeat packets (8B; 0 indicates "in progress," while the maximum value indicates an "error").
- 암호화가 완료되면 전송예고 패킷(8B, 총 전송 크기)을 보냅니다. Once encryption is complete, the sender transmits a transmission announcement packet (8B; total transmission size).
- 송신자는 데이터를 전송하고 수신자가 완료 패킷(8B)을 반송하여 통신을 끝냅니다. The sender transfers the data, and the receiver ends the communication by returning a completion packet (8B).

#### Standards

- data transfer: port 8001, gcm1
- file transfer: port 8002, gcmx1, zip1s
