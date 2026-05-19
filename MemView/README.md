## MemView

인-메모리 파일 뷰어 In-Memory file viewer

#### Golang

```go
struct MemView {
    Context string
    Names   []string
	Data    map[string][]byte
	CurMode int // 0: image, 1: text, 2: binary
	CurIdx  int
	OnSave  func(string, []byte)

    func Main(app fyne.App, title string, data map[string][]byte, onSave func(string, []byte), secure bool, txtlimit int)
}
```