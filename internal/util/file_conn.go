package util

import (
	"net"
	"os"
)

// FileConnAddr is the net.Addr of a conn backed by an os.File (the stdin/stdout pair of a
// STDIN listener).
type FileConnAddr struct {
	File *os.File
}

func (s *FileConnAddr) Network() string { return "file" }
func (s *FileConnAddr) String() string  { return s.File.Name() }

var _ net.Addr = (*FileConnAddr)(nil)
