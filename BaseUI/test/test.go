// go build -ldflags="-H windowsgui -s -w" -trimpath -o test.exe test.go
package main

import (
	"bytes"
	"errors"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/k-atusa/USAG-Lib/Bencrypt"
	"github.com/taewook427/USAG-KOX/BaseUI"
	"github.com/taewook427/USAG-KOX/TP1"
)

// TP1 sender
func sendBytes(w fyne.Window, data []byte, mask *Bencrypt.Masker) {
	if len(data) == 0 {
		dialog.ShowError(errors.New("No data available"), w)
		return
	}
	data, _ = mask.XOR(data)

	entIP := widget.NewEntry()
	entIP.SetPlaceHolder("IP:port (ex: 127.0.0.1:8001)")
	entSecret := widget.NewPasswordEntry()
	entSecret.SetPlaceHolder("shared secret")

	dialog.ShowCustomConfirm("Confirm Send", "Send", "Cancel", container.NewVBox(entIP, entSecret), func(b bool) {
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
			tp.Init(TP1.HASH_SHA3+TP1.SYM_GCM1+TP1.ASYM_ECC1, true, true, []byte(entSecret.Text), sock.Conn)

			_, _, err = tp.Send(bytes.NewReader(data), int64(len(data)), "")
			if err != nil {
				fyne.Do(func() { dialog.ShowError(err, w) })
			} else {
				fyne.Do(func() { dialog.ShowInformation("Success", "Transmit completed", w) })
			}
		}()
	}, w)
}

func main() {
	myApp := app.New()
	myApp.Settings().SetTheme(&BaseUI.U1Theme{})
	w := myApp.NewWindow("BaseUI Components Test")
	w.Resize(fyne.NewSize(800, 600))

	// 1. File selection
	var targets []string
	var selectedIdx int = -1

	list := widget.NewList(
		func() int { return len(targets) },
		func() fyne.CanvasObject { return widget.NewLabel("File or Folder Path") },
		func(i widget.ListItemID, o fyne.CanvasObject) { o.(*widget.Label).SetText(targets[i]) },
	)
	list.OnSelected = func(id widget.ListItemID) { selectedIdx = int(id) }
	list.OnUnselected = func(id widget.ListItemID) { selectedIdx = -1 }

	btnAddFiles := widget.NewButton("Add Files", func() { BaseUI.ListAddFile(list, &targets) })
	btnAddFolder := widget.NewButton("Add Dir", func() { BaseUI.ListAddFolder(list, &targets) })
	btnDelSel := widget.NewButton("Delete", func() {
		if selectedIdx >= 0 {
			BaseUI.ListDelTgt(list, &targets, selectedIdx)
			list.UnselectAll()
		}
	})
	btnDelAll := widget.NewButton("Reset", func() {
		BaseUI.ListDelTgt(list, &targets, len(targets))
		list.UnselectAll()
	})

	boxListBtn := container.NewHBox(btnAddFiles, btnAddFolder, btnDelSel, btnDelAll)
	cardList := widget.NewCard("1. Selection List", "", container.NewBorder(boxListBtn, nil, nil, nil, list))

	// 2. key file
	mask := Bencrypt.GetMasker(-1)
	var keyFile []byte
	lblKF := widget.NewLabel("[0B 00000000] keyfile not selected")

	btnSelectKF := widget.NewButton("Select", func() { BaseUI.SelectKF(lblKF, &keyFile, mask) })
	entPortKF := widget.NewEntry()
	entPortKF.SetPlaceHolder("port/secret: 8001/...")
	btnReceiveKF := widget.NewButton("Receive", func() { BaseUI.ReceiveKF(w, lblKF, entPortKF, &keyFile, mask) })
	btnSendKF := widget.NewButton("Send Data", func() { sendBytes(w, keyFile, mask) })

	boxKF := container.NewVBox(
		lblKF,
		container.NewGridWithColumns(4, btnSelectKF, entPortKF, btnReceiveKF, btnSendKF),
	)
	cardKF := widget.NewCard("2. KeyFile", "", boxKF)

	// 3. public key
	basic, _ := mask.XOR([]byte("45670981"))
	var pubKey []byte
	lblPub := widget.NewLabel("[0B 00000000] pubkey not selected")

	btnSelectPub := widget.NewButton("Select", func() { BaseUI.SelectPub(lblPub, &pubKey, basic, mask) })
	entPortPub := widget.NewEntry()
	entPortPub.SetPlaceHolder("port/secret: 8002/...")
	btnReceivePub := widget.NewButton("Receive", func() { BaseUI.ReceivePub(w, lblPub, entPortPub, &pubKey, mask) })
	btnSendPub := widget.NewButton("Send Data", func() { sendBytes(w, pubKey, mask) })

	boxPub := container.NewVBox(
		lblPub,
		container.NewGridWithColumns(4, btnSelectPub, entPortPub, btnReceivePub, btnSendPub),
	)
	cardPub := widget.NewCard("3. Public Key", "", boxPub)

	// 4. layout
	split := container.NewVSplit(
		cardList,
		container.NewVBox(cardKF, cardPub),
	)
	split.Offset = 0.5
	w.SetContent(container.NewPadded(split))
	w.ShowAndRun()
}
