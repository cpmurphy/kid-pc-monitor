package protocol

import (
	"bufio"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxFrameBytes rejects absurd length prefixes; real frames are well under 1 KiB.
const MaxFrameBytes = 64 * 1024

// FrameStatus classifies the head of a buffer.
type FrameStatus string

const (
	FrameComplete   FrameStatus = "complete"
	FrameIncomplete FrameStatus = "incomplete"
	FrameNotFrame   FrameStatus = "not_frame"
)

// EncodeFrame prefixes body with its byte length on its own line.
func EncodeFrame(body string) []byte {
	return []byte(strconv.Itoa(len(body)) + "\n" + body)
}

func allDigits(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// frameLength parses an all-digits length prefix, rejecting values above
// MaxFrameBytes without overflowing on absurdly long digit runs.
func frameLength(head []byte) (int, error) {
	trimmed := strings.TrimLeft(string(head), "0")
	if len(trimmed) > 6 {
		return 0, bad("frame too large")
	}
	if trimmed == "" {
		return 0, nil
	}
	n, _ := strconv.Atoi(trimmed)
	if n > MaxFrameBytes {
		return 0, bad("frame too large")
	}
	return n, nil
}

// InspectFrame classifies the head of buf as a length-prefixed frame. For
// FrameComplete, body is the decoded frame and rest the leftover bytes.
func InspectFrame(buf []byte) (status FrameStatus, body string, rest []byte, err error) {
	newline := -1
	for i, c := range buf {
		if c == '\n' {
			newline = i
			break
		}
	}
	if newline == -1 {
		// A bare run of digits may be a prefix still arriving.
		if allDigits(buf) {
			return FrameIncomplete, "", buf, nil
		}
		return FrameNotFrame, "", buf, nil
	}
	head := buf[:newline]
	if !allDigits(head) {
		return FrameNotFrame, "", buf, nil
	}
	length, err := frameLength(head)
	if err != nil {
		return "", "", nil, err
	}
	payload := buf[newline+1:]
	if len(payload) < length {
		return FrameIncomplete, "", buf, nil
	}
	if !utf8.Valid(payload[:length]) {
		return "", "", nil, bad("frame is not valid UTF-8")
	}
	return FrameComplete, string(payload[:length]), payload[length:], nil
}

// ReadFrame reads exactly one length-prefixed frame. The conversation is
// strictly request/response, so r must not be shared with other readers.
func ReadFrame(r *bufio.Reader) (string, error) {
	var head []byte
	for {
		c, err := r.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return "", &ProtocolError{
					Code:              InvalidRequest,
					Message:           "connection closed before length prefix",
					ClosedBeforeFrame: true,
				}
			}
			return "", err
		}
		if c == '\n' {
			break
		}
		head = append(head, c)
		if len(head) > MaxFrameBytes {
			return "", bad("length prefix too long")
		}
	}
	if !allDigits(head) {
		return "", bad("expected a length-prefixed frame")
	}
	length, err := frameLength(head)
	if err != nil {
		return "", err
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return "", bad("connection closed mid-frame")
		}
		return "", err
	}
	if !utf8.Valid(payload) {
		return "", bad("frame is not valid UTF-8")
	}
	return string(payload), nil
}

// WriteFrame writes body as one length-prefixed frame.
func WriteFrame(w io.Writer, body string) error {
	_, err := w.Write(EncodeFrame(body))
	return err
}
