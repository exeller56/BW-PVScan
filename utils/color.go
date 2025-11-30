package utils

type Color string

const (
	ColorBlack   Color = "\u001b[30m"
	ColorRed     Color = "\u001b[31m"
	ColorGreen   Color = "\u001b[32m"
	ColorYellow  Color = "\u001b[33m"
	ColorBlue    Color = "\u001b[34m"
	ColorMagenta Color = "\u001b[35m"
	ColorCyan    Color = "\u001b[36m"
	ColorWhite   Color = "\u001b[37m"

	ColorBrightBlack   Color = "\u001b[90m"
	ColorBrightRed     Color = "\u001b[91m"
	ColorBrightGreen   Color = "\u001b[92m"
	ColorBrightYellow  Color = "\u001b[93m"
	ColorBrightBlue    Color = "\u001b[94m"
	ColorBrightMagenta Color = "\u001b[95m"
	ColorBrightCyan    Color = "\u001b[96m"
	ColorBrightWhite   Color = "\u001b[97m"

	BgBlack   Color = "\u001b[40m"
	BgRed     Color = "\u001b[41m"
	BgGreen   Color = "\u001b[42m"
	BgYellow  Color = "\u001b[43m"
	BgBlue    Color = "\u001b[44m"
	BgMagenta Color = "\u001b[45m"
	BgCyan    Color = "\u001b[46m"
	BgWhite   Color = "\u001b[47m"

	BgBrightBlack   Color = "\u001b[100m"
	BgBrightRed     Color = "\u001b[101m"
	BgBrightGreen   Color = "\u001b[102m"
	BgBrightYellow  Color = "\u001b[103m"
	BgBrightBlue    Color = "\u001b[104m"
	BgBrightMagenta Color = "\u001b[105m"
	BgBrightCyan    Color = "\u001b[106m"
	BgBrightWhite   Color = "\u001b[107m"

	StyleBold      Color = "\u001b[1m"
	StyleDim       Color = "\u001b[2m"
	StyleItalic    Color = "\u001b[3m"
	StyleUnderline Color = "\u001b[4m"
	StyleBlink     Color = "\u001b[5m"
	StyleReverse   Color = "\u001b[7m"
	StyleHidden    Color = "\u001b[8m"

	ColorReset Color = "\u001b[0m"
)
