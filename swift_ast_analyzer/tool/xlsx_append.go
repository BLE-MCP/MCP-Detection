package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/xuri/excelize/v2"
)

func ensureSheetHeader(f *excelize.File, sheet string) error {
	if idx, _ := f.GetSheetIndex(sheet); idx == -1 {
		if _, err := f.NewSheet(sheet); err != nil {
			return err
		}
		_ = f.SetCellValue(sheet, "A1", "Index")
		_ = f.SetCellValue(sheet, "B1", "Project")
		_ = f.SetCellValue(sheet, "C1", "Elapsed (ms)")
		_ = f.SetCellValue(sheet, "D1", "Elapsed (seconds)")
		_ = f.SetCellValue(sheet, "E1", "Elapsed (hh:mm:ss.fff)")
	}
	return nil
}

func main() {
	// 用法：xlsx_append <xlsxPath> <project> <ms> <sec> <hms>
	if len(os.Args) < 6 {
		fmt.Println("usage: xlsx_append <xlsxPath> <project> <ms> <sec> <hms>")
		os.Exit(2)
	}
	xlsxPath := os.Args[1]
	project := os.Args[2]
	ms := os.Args[3]
	sec := os.Args[4]
	hms := os.Args[5]

	const sheet = "PerProject"

	var f *excelize.File
	if _, err := os.Stat(xlsxPath); os.IsNotExist(err) {
		// 创建新文件及目录
		_ = os.MkdirAll(filepath.Dir(xlsxPath), os.ModePerm)
		f = excelize.NewFile()
		// 删除默认 Sheet1，统一只用 PerProject
		if idx, _ := f.GetSheetIndex("Sheet1"); idx != -1 {
			f.DeleteSheet("Sheet1")
		}
		if err := ensureSheetHeader(f, sheet); err != nil {
			fmt.Println("header err:", err)
			os.Exit(1)
		}
	} else {
		var err error
		f, err = excelize.OpenFile(xlsxPath)
		if err != nil {
			fmt.Println("open err:", err)
			os.Exit(1)
		}
		if err := ensureSheetHeader(f, sheet); err != nil {
			fmt.Println("header err:", err)
			_ = f.Close()
			os.Exit(1)
		}
	}

	rows, _ := f.GetRows(sheet)
	nextRow := len(rows) + 1
	nextIndex := nextRow - 1

	_ = f.SetCellValue(sheet, fmt.Sprintf("A%d", nextRow), nextIndex)
	_ = f.SetCellValue(sheet, fmt.Sprintf("B%d", nextRow), project)
	_ = f.SetCellValue(sheet, fmt.Sprintf("C%d", nextRow), ms)
	_ = f.SetCellValue(sheet, fmt.Sprintf("D%d", nextRow), sec)
	_ = f.SetCellValue(sheet, fmt.Sprintf("E%d", nextRow), hms)

	// 为了避免并发写入或文件锁问题，保存前 sleep 极短时间（保险）
	time.Sleep(10 * time.Millisecond)

	if err := f.SaveAs(xlsxPath); err != nil {
		fmt.Println("save err:", err)
		_ = f.Close()
		os.Exit(1)
	}
	_ = f.Close()
}
