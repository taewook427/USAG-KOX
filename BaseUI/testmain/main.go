// 테스트 앱 실행 방법: go run BaseUI_test_app.go
package main

import (
	"bytes"
	"errors"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/taewook427/USAG-KOX/BaseUI"
	"github.com/taewook427/USAG-KOX/TP1"
)

func main() {
	myApp := app.New()
	myApp.Settings().SetTheme(&BaseUI.U1Theme{})
	w := myApp.NewWindow("BaseUI Components Test")
	w.Resize(fyne.NewSize(800, 600))

	// ==========================================
	// 1. 파일과 폴더 선택 리스트
	// ==========================================
	var targets []string
	var selectedIdx int = -1

	// List 위젯 생성
	list := widget.NewList(
		func() int { return len(targets) },
		func() fyne.CanvasObject { return widget.NewLabel("File or Folder Path") },
		func(i widget.ListItemID, o fyne.CanvasObject) { o.(*widget.Label).SetText(targets[i]) },
	)
	list.OnSelected = func(id widget.ListItemID) { selectedIdx = int(id) }
	list.OnUnselected = func(id widget.ListItemID) { selectedIdx = -1 }

	// 버튼들
	btnAddFiles := widget.NewButton("파일(들) 추가", func() { BaseUI.ListAddFile(list, &targets) })
	btnAddFolder := widget.NewButton("폴더 추가", func() { BaseUI.ListAddFolder(list, &targets) })
	btnDelSel := widget.NewButton("선택 삭제", func() {
		if selectedIdx >= 0 {
			BaseUI.ListDelTgt(list, &targets, selectedIdx)
			list.UnselectAll()
		}
	})
	btnDelAll := widget.NewButton("전체 삭제", func() {
		BaseUI.ListDelTgt(list, &targets, len(targets)) // idx가 len(targets)이면 전체 삭제됨
		list.UnselectAll()
	})

	boxListBtn := container.NewHBox(btnAddFiles, btnAddFolder, btnDelSel, btnDelAll)
	cardList := widget.NewCard("1. 파일/폴더 선택 리스트", "", container.NewBorder(boxListBtn, nil, nil, nil, list))

	// ==========================================
	// 2. 키 파일 선택
	// ==========================================
	var keyFile []byte
	lblKF := widget.NewLabel("[0B 00000000] keyfile not selected")

	btnSelectKF := widget.NewButton("Select", func() { BaseUI.SelectKF(lblKF, &keyFile, nil) })
	entPortKF := widget.NewEntry()
	entPortKF.SetPlaceHolder("port/secret: 8001/...")
	btnReceiveKF := widget.NewButton("Receive", func() { BaseUI.ReceiveKF(w, lblKF, entPortKF, &keyFile, nil) })
	btnSendKF := widget.NewButton("Send Data", func() { sendBytes(w, keyFile) })

	boxKF := container.NewVBox(
		lblKF,
		container.NewHBox(btnSelectKF, entPortKF, btnReceiveKF, btnSendKF),
	)
	cardKF := widget.NewCard("2. 키 파일 선택 및 전송", "", boxKF)

	// ==========================================
	// 3. 공개키 선택
	// ==========================================
	var pubKey []byte
	lblPub := widget.NewLabel("[0B 00000000] pubkey not selected")

	btnSelectPub := widget.NewButton("Select", func() { BaseUI.SelectPub(lblPub, &pubKey, nil, nil) })
	entPortPub := widget.NewEntry()
	entPortPub.SetPlaceHolder("port/secret: 8002/...")
	btnReceivePub := widget.NewButton("Receive", func() { BaseUI.ReceivePub(w, lblPub, entPortPub, &pubKey, nil) })
	btnSendPub := widget.NewButton("Send Data", func() { sendBytes(w, pubKey) })

	boxPub := container.NewVBox(
		lblPub,
		container.NewHBox(btnSelectPub, entPortPub, btnReceivePub, btnSendPub),
	)
	cardPub := widget.NewCard("3. 공개키 선택 및 전송", "", boxPub)

	// ==========================================
	// 레이아웃 구성 및 실행
	// ==========================================
	split := container.NewVSplit(
		cardList,
		container.NewVBox(cardKF, cardPub),
	)
	split.Offset = 0.5 // 위아래 5:5 비율

	w.SetContent(container.NewPadded(split))
	w.ShowAndRun()
}

// ==========================================
// 헬퍼: 현재 선택된 byte 데이터를 TP1으로 전송
// ==========================================
func sendBytes(w fyne.Window, data []byte) {
	if len(data) == 0 {
		dialog.ShowError(errors.New("전송할 데이터가 선택되지 않았습니다"), w)
		return
	}

	entIP := widget.NewEntry()
	entIP.SetPlaceHolder("IP:port (ex: 127.0.0.1:8001)")
	entSecret := widget.NewPasswordEntry()
	entSecret.SetPlaceHolder("shared secret")

	dialog.ShowCustomConfirm("데이터 전송", "Send", "Cancel", container.NewVBox(entIP, entSecret), func(b bool) {
		if !b {
			return
		}
		addr := entIP.Text
		if addr == "" {
			addr = "127.0.0.1:8001"
		}

		go func() {
			sock := new(TP1.TCPsocket)
			err := sock.MakeConnection(addr)
			defer sock.Close()
			if err != nil {
				fyne.Do(func() { dialog.ShowError(err, w) })
				return
			}

			tp := new(TP1.TP1)
			tp.Init(0, true, false, []byte(entSecret.Text), sock.Conn)

			// 전송 실행
			_, _, err = tp.Send(bytes.NewReader(data), int64(len(data)), "")
			if err != nil {
				fyne.Do(func() { dialog.ShowError(err, w) })
			} else {
				fyne.Do(func() { dialog.ShowInformation("성공", "데이터 전송이 완료되었습니다.", w) })
			}
		}()
	}, w)
}
