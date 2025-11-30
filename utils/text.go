package utils

import (
	"fmt"
	"strings"
)

func CenterText(text string, width int) string {
	if len(text) >= width {
		return text
	}
	padding := (width - len(text)) / 2
	leftPadding := padding
	rightPadding := width - len(text) - leftPadding
	return strings.Repeat(" ", leftPadding) + text + strings.Repeat(" ", rightPadding)
}

func PrintCentered(text string) {
	width := 100
	padding := (width - len(text)) / 2
	if padding < 0 {
		padding = 0
	}
	fmt.Printf("%*s%s\n", padding, "", text)
}
