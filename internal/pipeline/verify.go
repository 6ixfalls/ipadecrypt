package pipeline

import (
	"archive/zip"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/londek/ipadecrypt/internal/macho"
)

type VerifyMismatch struct {
	Name   string
	Reason string
}

type VerifyResult struct {
	Scanned        int              // Mach-Os parsed in output IPA
	Compared       int              // additionally byte-checked against source
	StillEncrypted []string         // cryptid != 0 (decrypt didn't write through)
	AllZeroCrypt   []string         // cryptid == 0 but crypt region all zeros (decrypt-on-fault never fired)
	Mismatches     []VerifyMismatch // bytes outside crypt region differ from source
	Missing        []string         // output entry has no source counterpart (only when source given)
	Skipped        []string         // output Mach-O failed to parse
}

func (r VerifyResult) OK() bool {
	return len(r.StillEncrypted) == 0 &&
		len(r.AllZeroCrypt) == 0 &&
		len(r.Mismatches) == 0
}

// Verify scans every Mach-O in the decrypted output IPA, asserting
// cryptid==0 and that the FairPlay crypt region isn't a zero-fill (a
// signal that helper decrypt-on-fault never actually fired). When
// sourceIPA is non-empty, each output is also byte-compared against
// its source slice outside the cryptid byte and the encrypted region,
// catching cryptid-zeroed-without-decrypting and any out-of-band byte
// corruption. When skipAppex is true, entries under Payload/<App>.app
// /PlugIns/ are ignored - the helper left them encrypted on purpose.
//
// Output is THIN - helper drops fat siblings - so each output entry
// maps to one specific slice in a (possibly fat) source.
func Verify(outputIPA, sourceIPA string, skipAppex bool) (VerifyResult, error) {
	var res VerifyResult

	out, err := zip.OpenReader(outputIPA)
	if err != nil {
		return res, fmt.Errorf("open output %s: %w", outputIPA, err)
	}
	defer out.Close()

	var srcByName map[string]*zip.File

	if sourceIPA != "" {
		src, err := zip.OpenReader(sourceIPA)
		if err != nil {
			return res, fmt.Errorf("open source %s: %w", sourceIPA, err)
		}
		defer src.Close()

		srcByName = make(map[string]*zip.File, len(src.File))
		for _, f := range src.File {
			srcByName[f.Name] = f
		}
	}

	for _, of := range out.File {
		if !strings.HasPrefix(of.Name, "Payload/") || of.FileInfo().IsDir() {
			continue
		}

		if skipAppex && isAppExtPath(of.Name) {
			continue
		}

		outData, isMacho, err := readMachO(of)
		if err != nil {
			return res, fmt.Errorf("read %s: %w", of.Name, err)
		}

		if !isMacho {
			continue
		}
		res.Scanned++

		encrypted, err := sliceHasCryptid(outData)
		if err != nil {
			res.Skipped = append(res.Skipped, of.Name)
			continue
		}

		if encrypted {
			res.StillEncrypted = append(res.StillEncrypted, of.Name)
			continue
		}

		// Source-bearing path: precise compare (handles its own all-zero
		// check, gated on srcCrypt.Cryptid to avoid false positives on
		// legitimately-plaintext passthrough slices).
		if sf := srcByName[of.Name]; sf != nil {
			srcData, srcIsMacho, err := readMachO(sf)
			if err != nil {
				return res, fmt.Errorf("read source %s: %w", of.Name, err)
			}

			// Source isn't Mach-O (TBD stubs, .a archives, resolved
			// symlinks) - nothing FairPlay touches, skip.
			if !srcIsMacho {
				continue
			}
			if reason := compareMachOSlice(outData, srcData); reason != "" {
				res.Mismatches = append(res.Mismatches, VerifyMismatch{Name: of.Name, Reason: reason})
				continue
			}

			res.Compared++
			continue
		}

		if srcByName != nil {
			res.Missing = append(res.Missing, of.Name)
		}

		// Source-free fallback: flag thin outputs whose entire crypt
		// region is zeros. False positives are possible if the source
		// shipped LC_ENCRYPTION_INFO with cryptid==0 over a genuinely
		// zero region - rare, and source-aware verify catches it.
		if cryptZeroed(outData) {
			res.AllZeroCrypt = append(res.AllZeroCrypt, of.Name)
		}
	}

	return res, nil
}

type archiveMachO struct {
	file *zip.File
	size uint64
}

// readMachO identifies a Mach-O from its four-byte magic without retaining the
// ZIP entry. Later parser and comparison passes reopen the entry and stream only
// the ranges they need. (nil, false, nil) signals "not a Mach-O, skip".
func readMachO(f *zip.File) (*archiveMachO, bool, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, false, err
	}
	defer rc.Close()

	var head [4]byte
	if n, _ := io.ReadFull(rc, head[:]); n < 4 || !macho.IsMagic(head[:]) {
		return nil, false, nil
	}
	remaining, err := io.Copy(io.Discard, rc)
	if err != nil {
		return nil, false, err
	}
	if uint64(remaining)+uint64(len(head)) != f.UncompressedSize64 {
		return nil, false, io.ErrUnexpectedEOF
	}

	return &archiveMachO{file: f, size: f.UncompressedSize64}, true, nil
}

type machoSlice struct {
	offset uint64
	size   uint64
	cpu    uint32
	sub    uint32
	crypt  *macho.EncryptionInfo
}

func readAt(m *archiveMachO, offset uint64, p []byte) error {
	if offset > m.size || uint64(len(p)) > m.size-offset {
		return io.ErrUnexpectedEOF
	}
	r, err := m.file.Open()
	if err != nil {
		return err
	}
	defer r.Close()
	if offset > 1<<63-1 {
		return fmt.Errorf("entry offset exceeds supported range")
	}
	if _, err = io.CopyN(io.Discard, r, int64(offset)); err != nil {
		return err
	}
	_, err = io.ReadFull(r, p)
	return err
}

func thinSlice(m *archiveMachO, offset, size uint64) (machoSlice, error) {
	s := machoSlice{offset: offset, size: size}
	if size < 28 || offset > m.size || size > m.size-offset {
		return s, fmt.Errorf("mach_header truncated")
	}
	var header [32]byte
	if err := readAt(m, offset, header[:28]); err != nil {
		return s, err
	}
	magic := binary.LittleEndian.Uint32(header[:4])
	var bo binary.ByteOrder = binary.LittleEndian
	is64 := magic == macho.Magic64LE || magic == macho.Magic64BE
	if magic == macho.MagicBE || magic == macho.Magic64BE {
		bo = binary.BigEndian
	} else if magic != macho.MagicLE && magic != macho.Magic64LE {
		return s, fmt.Errorf("not a thin Mach-O magic=0x%x", magic)
	}
	headerSize := uint64(28)
	if is64 {
		headerSize = 32
		if err := readAt(m, offset, header[:32]); err != nil {
			return s, err
		}
	}
	s.cpu = bo.Uint32(header[4:8])
	s.sub = bo.Uint32(header[8:12])
	ncmds := bo.Uint32(header[16:20])
	sizeofcmds := uint64(bo.Uint32(header[20:24]))
	if headerSize+sizeofcmds > size {
		return s, fmt.Errorf("load commands truncated")
	}
	p := headerSize
	for range ncmds {
		var cmdHeader [8]byte
		if p+8 > headerSize+sizeofcmds || readAt(m, offset+p, cmdHeader[:]) != nil {
			return s, fmt.Errorf("load cmd truncated")
		}
		cmd := bo.Uint32(cmdHeader[:4])
		cmdSize := uint64(bo.Uint32(cmdHeader[4:]))
		if cmdSize < 8 || cmdSize > headerSize+sizeofcmds-p {
			return s, fmt.Errorf("bad cmdsize=%d", cmdSize)
		}
		want := uint32(macho.LCEncryptionInfo)
		if is64 {
			want = macho.LCEncryptionInfo64
		}
		if cmd == want {
			if cmdSize < 20 {
				return s, fmt.Errorf("LC_ENCRYPTION_INFO truncated")
			}
			var enc [20]byte
			if err := readAt(m, offset+p, enc[:]); err != nil {
				return s, err
			}
			info := macho.EncryptionInfo{
				CryptOff:      uint64(bo.Uint32(enc[8:12])),
				CryptSize:     uint64(bo.Uint32(enc[12:16])),
				CryptidOffset: p + 16,
				Cryptid:       bo.Uint32(enc[16:20]),
			}
			if info.CryptOff > size || info.CryptSize > size-info.CryptOff {
				return s, fmt.Errorf("encrypted region out of range")
			}
			s.crypt = &info
		}
		p += cmdSize
	}
	return s, nil
}

func machoSlices(m *archiveMachO) ([]machoSlice, bool, error) {
	var head [8]byte
	if err := readAt(m, 0, head[:4]); err != nil {
		return nil, false, err
	}
	magic := binary.LittleEndian.Uint32(head[:4])
	if magic == macho.MagicLE || magic == macho.Magic64LE ||
		magic == macho.MagicBE || magic == macho.Magic64BE {
		s, err := thinSlice(m, 0, m.size)
		return []machoSlice{s}, false, err
	}
	is64 := magic == macho.FatMagic64 || magic == macho.FatCigam64
	if !is64 && magic != macho.FatMagic && magic != macho.FatCigam {
		return nil, false, fmt.Errorf("not a Mach-O")
	}
	if err := readAt(m, 0, head[:]); err != nil {
		return nil, true, err
	}
	nfat := binary.BigEndian.Uint32(head[4:8])
	if nfat == 0 || nfat > 32 {
		return nil, true, fmt.Errorf("implausible nfat_arch=%d", nfat)
	}
	archSize := uint64(20)
	if is64 {
		archSize = 32
	}
	result := make([]machoSlice, 0, nfat)
	for i := uint32(0); i < nfat; i++ {
		entry := make([]byte, archSize)
		if err := readAt(m, 8+uint64(i)*archSize, entry); err != nil {
			return nil, true, fmt.Errorf("fat_arch truncated")
		}
		var off, size uint64
		if is64 {
			off = binary.BigEndian.Uint64(entry[8:16])
			size = binary.BigEndian.Uint64(entry[16:24])
		} else {
			off = uint64(binary.BigEndian.Uint32(entry[8:12]))
			size = uint64(binary.BigEndian.Uint32(entry[12:16]))
		}
		s, err := thinSlice(m, off, size)
		if err != nil {
			return nil, true, err
		}
		result = append(result, s)
	}
	return result, true, nil
}

func sliceHasCryptid(m *archiveMachO) (bool, error) {
	slices, _, err := machoSlices(m)
	if err != nil {
		return false, err
	}
	for _, s := range slices {
		if s.crypt != nil && s.crypt.Cryptid != 0 {
			return true, nil
		}
	}
	return false, nil
}

func cryptZeroed(m *archiveMachO) bool {
	slices, isFat, err := machoSlices(m)
	if err != nil || isFat || len(slices) != 1 || slices[0].crypt == nil || slices[0].crypt.CryptSize == 0 {
		return false
	}
	s := slices[0]
	return rangeAllZero(m, s.offset+s.crypt.CryptOff, s.crypt.CryptSize)
}

// compareMachOSlice returns "" when the output is consistent with the
// source. Two cases:
//   - Output fat → helper didn't touch (no FairPlay slice); must match
//     source verbatim.
//   - Output thin → helper decrypted one slice and dropped fat siblings;
//     pick the matching cputype slice in source and byte-compare outside
//     the encrypted region + cryptid byte.
func compareMachOSlice(outData, srcData *archiveMachO) string {
	outSlices, outIsFat, err := machoSlices(outData)
	if err != nil || len(outSlices) == 0 {
		return "parse output: " + err.Error()
	}
	if outIsFat {
		if outData.size != srcData.size || !rangesEqual(outData, 0, srcData, 0, outData.size) {
			return "fat passthrough differs from source"
		}
		return ""
	}
	outSlice := outSlices[0]
	srcSlices, _, err := machoSlices(srcData)
	if err != nil {
		return "match source slice: " + err.Error()
	}
	var srcSlice *machoSlice
	for i := range srcSlices {
		if srcSlices[i].cpu == outSlice.cpu && srcSlices[i].sub&0x00ffffff == outSlice.sub&0x00ffffff {
			srcSlice = &srcSlices[i]
			break
		}
	}
	if srcSlice == nil {
		return fmt.Sprintf("match source slice: source cpu mismatch: want (0x%x,0x%x)", outSlice.cpu, outSlice.sub)
	}
	if outSlice.crypt == nil {
		// No LC_ENCRYPTION_INFO in output - slice was never encrypted.
		// Direct compare without the cryptid/cryptoff skip.
		if outSlice.size == srcSlice.size && rangesEqual(outData, outSlice.offset, srcData, srcSlice.offset, outSlice.size) {
			return ""
		}
		return "thin passthrough differs from source slice"
	}
	if srcSlice.crypt == nil {
		return "parse source LC_ENCRYPTION_INFO: no LC_ENCRYPTION_INFO load command"
	}
	outCrypt, srcCrypt := outSlice.crypt, srcSlice.crypt

	// Helper only patches cryptid and decrypts bytes - never moves
	// cryptoff or cryptsize.
	if outCrypt.CryptOff != srcCrypt.CryptOff ||
		outCrypt.CryptSize != srcCrypt.CryptSize {
		return fmt.Sprintf(
			"cryptoff/cryptsize moved: output=(%d,%d) source=(%d,%d)",
			outCrypt.CryptOff, outCrypt.CryptSize,
			srcCrypt.CryptOff, srcCrypt.CryptSize,
		)
	}

	if outSlice.size != srcSlice.size {
		return fmt.Sprintf("size differs: output=%d source=%d", outSlice.size, srcSlice.size)
	}

	cryptidEnd := outCrypt.CryptidOffset + 4
	cryptEnd := outCrypt.CryptOff + outCrypt.CryptSize

	if !rangesEqual(outData, outSlice.offset, srcData, srcSlice.offset, outCrypt.CryptidOffset) {
		return "header diff before cryptid"
	}

	if cryptidEnd > outCrypt.CryptOff || !rangesEqual(outData, outSlice.offset+cryptidEnd, srcData, srcSlice.offset+cryptidEnd, outCrypt.CryptOff-cryptidEnd) {
		return "header/load-commands diff between cryptid and cryptoff"
	}

	if cryptEnd < outSlice.size && !rangesEqual(outData, outSlice.offset+cryptEnd, srcData, srcSlice.offset+cryptEnd, outSlice.size-cryptEnd) {
		return "diff after encrypted region (LINKEDIT/etc)"
	}

	// Source already plaintext: bytes must match verbatim, and the
	// "decrypt bailed" heuristics below would false-flag.
	if srcCrypt.Cryptid == 0 {
		return ""
	}

	if rangeAllZero(outData, outSlice.offset+outCrypt.CryptOff, outCrypt.CryptSize) {
		return "crypt region is all zeros (FairPlay decrypt-on-fault never fired in target)"
	}

	if rangesEqual(outData, outSlice.offset+outCrypt.CryptOff, srcData, srcSlice.offset+srcCrypt.CryptOff, outCrypt.CryptSize) {
		return "crypt region byte-equal to source ciphertext (cryptid zeroed without decrypting)"
	}

	return ""
}

func rangesEqual(a *archiveMachO, aOffset uint64, b *archiveMachO, bOffset, size uint64) bool {
	if aOffset > a.size || size > a.size-aOffset || bOffset > b.size || size > b.size-bOffset {
		return false
	}
	ar, err := openRange(a, aOffset)
	if err != nil {
		return false
	}
	defer ar.Close()
	br, err := openRange(b, bOffset)
	if err != nil {
		return false
	}
	defer br.Close()
	var ab, bb [64 << 10]byte
	for size > 0 {
		n := uint64(len(ab))
		if size < n {
			n = size
		}
		if _, err = io.ReadFull(ar, ab[:n]); err != nil {
			return false
		}
		if _, err = io.ReadFull(br, bb[:n]); err != nil {
			return false
		}
		for i := uint64(0); i < n; i++ {
			if ab[i] != bb[i] {
				return false
			}
		}
		aOffset, bOffset, size = aOffset+n, bOffset+n, size-n
	}
	return true
}

func rangeAllZero(m *archiveMachO, offset, size uint64) bool {
	if offset > m.size || size > m.size-offset {
		return false
	}
	r, err := openRange(m, offset)
	if err != nil {
		return false
	}
	defer r.Close()
	var buf [64 << 10]byte
	for size > 0 {
		n := uint64(len(buf))
		if size < n {
			n = size
		}
		if _, err = io.ReadFull(r, buf[:n]); err != nil {
			return false
		}
		for _, c := range buf[:n] {
			if c != 0 {
				return false
			}
		}
		offset, size = offset+n, size-n
	}
	return true
}

func openRange(m *archiveMachO, offset uint64) (io.ReadCloser, error) {
	if offset > m.size || offset > 1<<63-1 {
		return nil, io.ErrUnexpectedEOF
	}
	r, err := m.file.Open()
	if err != nil {
		return nil, err
	}
	if _, err = io.CopyN(io.Discard, r, int64(offset)); err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}
