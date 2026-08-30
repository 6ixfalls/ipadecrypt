//go:build windows

package unicorn

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/bodgit/sevenzip"
	"github.com/klauspost/compress/zstd"
)

func openArchiveEntry(path, name string, format archiveFormat) (archiveEntry, error) {
	switch format {
	case archiveZIP:
		return openZIPEntry(path, name)
	case archiveSevenZip:
		return openSevenZipEntry(path, name)
	case archiveTarZstd:
		return openTarZstdEntry(path, name)
	default:
		return archiveEntry{}, fmt.Errorf("unsupported Unicorn archive format %d", format)
	}
}

func openSevenZipEntry(path, name string) (archiveEntry, error) {
	archive, err := sevenzip.OpenReader(path)
	if err != nil {
		return archiveEntry{}, fmt.Errorf("open Unicorn archive: %w", err)
	}

	for _, candidate := range archive.File {
		if candidate.Name != name {
			continue
		}

		if candidate.FileInfo().IsDir() {
			_ = archive.Close()
			return archiveEntry{}, fmt.Errorf("invalid Unicorn library entry %q", name)
		}

		reader, err := candidate.Open()
		if err != nil {
			_ = archive.Close()
			return archiveEntry{}, fmt.Errorf("open Unicorn library entry: %w", err)
		}

		return archiveEntry{
			reader: reader,
			size:   candidate.UncompressedSize,
			close: func() error {
				return errors.Join(reader.Close(), archive.Close())
			},
		}, nil
	}

	_ = archive.Close()

	return archiveEntry{}, fmt.Errorf("unicorn archive does not contain %q", name)
}

func openTarZstdEntry(path, name string) (archiveEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return archiveEntry{}, fmt.Errorf("open Unicorn archive: %w", err)
	}

	decoder, err := zstd.NewReader(file)
	if err != nil {
		_ = file.Close()

		return archiveEntry{}, fmt.Errorf("open Unicorn archive: %w", err)
	}

	closeArchive := func() error {
		decoder.Close()

		return file.Close()
	}

	reader := tar.NewReader(decoder)

	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			_ = closeArchive()

			return archiveEntry{}, fmt.Errorf("unicorn archive does not contain %q", name)
		}

		if err != nil {
			_ = closeArchive()

			return archiveEntry{}, fmt.Errorf("read Unicorn archive: %w", err)
		}

		if header.Name != name {
			continue
		}

		if header.Typeflag != tar.TypeReg || header.Size < 0 {
			_ = closeArchive()

			return archiveEntry{}, fmt.Errorf("invalid Unicorn library entry %q", name)
		}

		return archiveEntry{
			reader: io.LimitReader(reader, header.Size),
			size:   uint64(header.Size),
			close:  closeArchive,
		}, nil
	}
}
