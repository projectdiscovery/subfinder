package log

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/logrusorgru/aurora"
)

// Level defines all the available levels we can log at
type Level int

// Available logging levels
const (
	Null Level = iota
	Fatal
	Silent
	Label
	Misc
	Error
	Info
	Warning
	Verbose
)

var (
	// UseColors can be used to control coloring of the output
	UseColors = true
	// MaxLevel is the maximum level to log at. By default, logging
	// is done at Info level. Using verbose will display all the errors too,
	// Using silent will display only the most relevant information.
	MaxLevel = Info

	labels = map[Level]string{
		Warning: "WRN",
		Error:   "ERR",
		Label:   "WRN",
		Fatal:   "FTL",
		Info:    "INF",
	}
)

var stringBuilderPool = &sync.Pool{New: func() interface{} {
	return new(strings.Builder)
}}

// wrap wraps a given label for a message to a logg-able representation.
// It checks if colors are specified and what level we are logging at.
func wrap(label string, level Level) string {
	// Check if we are not using colors, if not, return
	if !UseColors {
		return label
	}

	switch level {
	case Silent:
		return label
	case Info, Verbose:
		return aurora.Blue(label).String()
	case Fatal:
		return aurora.Bold(aurora.Red(label)).String()
	case Error:
		return aurora.Red(label).String()
	case Warning, Label:
		return aurora.Yellow(label).String()
	default:
		return label
	}
}

// getLabel generates a label for a given message, depending on the level
// and the label passed.
func getLabel(level Level, label string, sb *strings.Builder) {
	switch level {
	case Silent, Misc:
		return
	case Error, Fatal, Info, Warning, Label:
		sb.WriteString("[")
		sb.WriteString(wrap(labels[level], level))
		sb.WriteString("]")
		sb.WriteString(" ")
		return
	case Verbose:
		sb.WriteString("[")
		sb.WriteString(wrap(label, level))
		sb.WriteString("]")
		sb.WriteString(" ")
		return
	default:
		return
	}
}

// log logs the actual message to the screen
func log(level Level, label string, format string, args ...interface{}) {
	// Don't log if the level is null
	if level == Null {
		return
	}

	if level <= MaxLevel {
		// Build the log message using the string builder pool
		sb := stringBuilderPool.Get().(*strings.Builder)

		// Get the label and append it to string builder
		getLabel(level, label, sb)

		message := fmt.Sprintf(format, args...)
		sb.WriteString(message)

		if strings.HasSuffix(message, "\n") == false {
			sb.WriteString("\n")
		}

		switch level {
		case Silent:
			fmt.Fprintf(os.Stdout, sb.String())
		default:
			fmt.Fprintf(os.Stderr, sb.String())
		}

		sb.Reset()
		stringBuilderPool.Put(sb)
	}
}

// Infof writes a info message on the screen with the default label
func Infof(format string, args ...interface{}) {
	log(Info, "", format, args...)
}

// Warningf writes a warning message on the screen with the default label
func Warningf(format string, args ...interface{}) {
	log(Warning, "", format, args...)
}

// Errorf writes an error message on the screen with the default label
func Errorf(format string, args ...interface{}) {
	log(Error, "", format, args...)
}

// Verbosef writes a verbose message on the screen with a tabel
func Verbosef(format string, label string, args ...interface{}) {
	log(Verbose, label, format, args...)
}

// Silentf writes a message on the stdout with no label
func Silentf(format string, args ...interface{}) {
	log(Silent, "", format, args...)
}

// Fatalf exits the program if we encounter a fatal error
func Fatalf(format string, args ...interface{}) {
	log(Fatal, "", format, args...)
	os.Exit(1)
}

// Printf prints a string on screen without any extra stuff
func Printf(format string, args ...interface{}) {
	log(Misc, "", format, args...)
}

// Labelf prints a string on screen with a label interface
func Labelf(format string, args ...interface{}) {
	log(Label, "", format, args...)
}
