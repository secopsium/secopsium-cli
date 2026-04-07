package main

import (
	"errors"
	"fmt"
	"os"
)

func main() {
	if err := Execute(); err != nil {
		var exitErr *ExitCodeError
		if errors.As(err, &exitErr) {
			if exitErr.Err != nil {
				fmt.Fprintln(os.Stderr, exitErr.Err)
			}
			os.Exit(exitErr.Code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
