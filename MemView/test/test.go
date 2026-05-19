// go build -ldflags="-H windowsgui -s -w" -trimpath -o test.exe test.go
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/taewook427/USAG-KOX/BaseUI"
	"github.com/taewook427/USAG-KOX/MemView"
)

func main() {
	// 1. main window
	myApp := app.New()
	myApp.Settings().SetTheme(BaseUI.U1Theme{})
	mainWindow := myApp.NewWindow("Test Viewer")

	btnOpenViewer := widget.NewButton("Select Files", func() {
		paths, err := BaseUI.ZenityMultiFiles("")
		if err != nil {
			dialog.ShowError(err, mainWindow)
			return
		}
		if len(paths) == 0 {
			return
		}

		// make map to store file data
		fileDataMap := make(map[string][]byte)
		for _, path := range paths {
			data, err := os.ReadFile(path)
			if err != nil {
				dialog.ShowError(err, mainWindow)
				continue
			}
			fileDataMap[filepath.Base(path)] = data
		}

		// MemView instance
		viewer := new(MemView.MemView)
		writeBack := func(name string, updatedData []byte) {
			dialog.ShowInformation("Virtual Write", fmt.Sprintf("writed %s (%d B)", name, len(updatedData)), mainWindow)
		}
		viewer.Main(myApp, "Memory Viewer", fileDataMap, writeBack, true, 0)
	})

	// layout
	mainWindow.SetContent(container.NewCenter(btnOpenViewer))
	mainWindow.Resize(fyne.NewSize(400, 200))
	mainWindow.CenterOnScreen()
	mainWindow.ShowAndRun()
}
