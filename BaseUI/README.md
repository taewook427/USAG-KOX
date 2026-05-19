## BaseUI

테마와 파일 선택 등 GUI 기본 보조기능

Basic GUI auxiliary functions such as theme and file selection

#### Golang

```go
FyneSize float32
struct U1Theme

ZenNames []string
ZenTypes [][]string
func ZenityFile(title string) (res string, err error)
func ZenityMultiFiles(title string) (res []string, err error)
func ZenityFolder(title string) (res string, err error)

func SelectKF(lbl *widget.Label, keyPtr *[]byte, mask *Bencrypt.Masker)
func ReceiveKF(w fyne.Window, lbl *widget.Label, portEnt *widget.Entry, keyPtr *[]byte, mask *Bencrypt.Masker)
func ChooseKF(lbl *widget.Label, keyPtr *[]byte, sel string, mp map[string][]byte, mask *Bencrypt.Masker)
func SelectPub(lbl *widget.Label, keyPtr *[]byte, basic []byte, mask *Bencrypt.Masker)
func ReceivePub(w fyne.Window, lbl *widget.Label, portEnt *widget.Entry, keyPtr *[]byte, mask *Bencrypt.Masker)

func ListAddFile(l *widget.List, tgts *[]string)
func ListAddFolder(l *widget.List, tgts *[]string)
func ListDelTgt(l *widget.List, tgts *[]string, idx int)
```