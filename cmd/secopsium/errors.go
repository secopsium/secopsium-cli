package main

type ExitCodeError struct {
	Code int
	Err  error
}

func (e *ExitCodeError) Error() string {
	if e.Err == nil {
		return "command failed"
	}
	return e.Err.Error()
}

func NewExitCodeError(code int, err error) *ExitCodeError {
	return &ExitCodeError{Code: code, Err: err}
}
