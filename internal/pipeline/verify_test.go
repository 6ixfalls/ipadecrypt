package pipeline

import (
	"archive/zip"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/londek/ipadecrypt/internal/macho"
)

func TestVerifyStreamsMachOComparison(t *testing.T) {
	t.Parallel()

	const cryptSize = 8 << 20
	source := testMachO(1, 0xaa, cryptSize)
	output := testMachO(0, 0xbb, cryptSize)
	dir := t.TempDir()
	sourceIPA := filepath.Join(dir, "source.ipa")
	outputIPA := filepath.Join(dir, "output.ipa")
	writeTestIPA(t, sourceIPA, source)
	writeTestIPA(t, outputIPA, output)

	result, err := Verify(outputIPA, sourceIPA, false)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK() || result.Scanned != 1 || result.Compared != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestVerifyDetectsUnchangedCiphertext(t *testing.T) {
	t.Parallel()

	source := testMachO(1, 0xaa, 1<<20)
	output := testMachO(0, 0xaa, 1<<20)
	dir := t.TempDir()
	sourceIPA := filepath.Join(dir, "source.ipa")
	outputIPA := filepath.Join(dir, "output.ipa")
	writeTestIPA(t, sourceIPA, source)
	writeTestIPA(t, outputIPA, output)

	result, err := Verify(outputIPA, sourceIPA, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.OK() || len(result.Mismatches) != 1 || result.Mismatches[0].Reason != "crypt region byte-equal to source ciphertext (cryptid zeroed without decrypting)" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestVerifyDetectsZeroFilledCryptRegionWithoutSource(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outputIPA := filepath.Join(dir, "output.ipa")
	writeTestIPA(t, outputIPA, testMachO(0, 0, 1<<20))

	result, err := Verify(outputIPA, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if result.OK() || len(result.AllZeroCrypt) != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestVerifyMatchesThinOutputToFatSourceSlice(t *testing.T) {
	t.Parallel()

	sourceSlice := testMachO(1, 0xaa, 1<<20)
	otherSlice := testMachO(0, 0xcc, 4096)
	// Give the sibling a different CPU so slice selection cannot pick it.
	binary.LittleEndian.PutUint32(otherSlice[4:8], 0x01000007)
	fatSource := testFatMachO(otherSlice, sourceSlice)
	output := testMachO(0, 0xbb, 1<<20)
	dir := t.TempDir()
	sourceIPA := filepath.Join(dir, "source.ipa")
	outputIPA := filepath.Join(dir, "output.ipa")
	writeTestIPA(t, sourceIPA, fatSource)
	writeTestIPA(t, outputIPA, output)

	result, err := Verify(outputIPA, sourceIPA, false)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK() || result.Compared != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func testMachO(cryptid uint32, cryptByte byte, cryptSize int) []byte {
	const (
		headerSize  = 32
		commandSize = 24
		cryptOff    = 4096
	)
	data := make([]byte, cryptOff+cryptSize+4096)
	binary.LittleEndian.PutUint32(data[0:4], macho.Magic64LE)
	binary.LittleEndian.PutUint32(data[4:8], 0x0100000c)
	binary.LittleEndian.PutUint32(data[8:12], 0)
	binary.LittleEndian.PutUint32(data[16:20], 1)
	binary.LittleEndian.PutUint32(data[20:24], commandSize)
	binary.LittleEndian.PutUint32(data[headerSize:headerSize+4], macho.LCEncryptionInfo64)
	binary.LittleEndian.PutUint32(data[headerSize+4:headerSize+8], commandSize)
	binary.LittleEndian.PutUint32(data[headerSize+8:headerSize+12], cryptOff)
	binary.LittleEndian.PutUint32(data[headerSize+12:headerSize+16], uint32(cryptSize))
	binary.LittleEndian.PutUint32(data[headerSize+16:headerSize+20], cryptid)
	for i := cryptOff; i < cryptOff+cryptSize; i++ {
		data[i] = cryptByte
	}
	return data
}

func testFatMachO(slices ...[]byte) []byte {
	const align = 4096
	headerSize := 8 + 20*len(slices)
	offset := (headerSize + align - 1) &^ (align - 1)
	total := offset
	for _, slice := range slices {
		total += (len(slice) + align - 1) &^ (align - 1)
	}
	data := make([]byte, total)
	binary.BigEndian.PutUint32(data[:4], macho.FatMagic)
	binary.BigEndian.PutUint32(data[4:8], uint32(len(slices)))
	for i, slice := range slices {
		entry := data[8+i*20 : 8+(i+1)*20]
		binary.BigEndian.PutUint32(entry[0:4], binary.LittleEndian.Uint32(slice[4:8]))
		binary.BigEndian.PutUint32(entry[4:8], binary.LittleEndian.Uint32(slice[8:12]))
		binary.BigEndian.PutUint32(entry[8:12], uint32(offset))
		binary.BigEndian.PutUint32(entry[12:16], uint32(len(slice)))
		copy(data[offset:], slice)
		offset += (len(slice) + align - 1) &^ (align - 1)
	}
	return data
}

func writeTestIPA(t *testing.T, path string, executable []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("Payload/Test.app/Test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(executable); err != nil {
		t.Fatal(err)
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
}
