package device

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOperationPaths(t *testing.T) {
	for _, p := range []string{"/var/containers/Bundle/Application/../Test.app", "/var/containers/Bundle/Application/X/../../Test.app", "/var/containers/Bundle/Application/X/Y/Z.app", "/var/containers/Bundle/Application/X/.app", "/var/containers/Bundle/Application/X"} {
		if ValidBundlePath(p) {
			t.Fatalf("accepted %q", p)
		}
	}

	if !ValidBundlePath("/var/containers/Bundle/Application/UUID/Test.app") {
		t.Fatal("valid bundle rejected")
	}

	for _, token := range []string{"../other", "", "a/b", strings.Repeat("a", 63)} {
		if validOperationRoot(OperationRoot(token)) {
			t.Fatal("unsafe root accepted")
		}
	}

	if !validOperationRoot(OperationRoot(strings.Repeat("a", 64))) {
		t.Fatal("valid root rejected")
	}
}
func TestNativeOperationProtocol(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX helper protocol")
	}

	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler unavailable")
	}

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	prefix := filepath.Join(root, "ipadecrypt-op-")
	binary := filepath.Join(root, "operation-test")

	args := []string{"-std=c11", "-D_DEFAULT_SOURCE", "-DOPERATION_PREFIX=\"" + prefix + "\"", "../../helper/operation_test.c", "../../helper/log.c", "-o", binary}
	if runtime.GOOS == "linux" {
		args = append(args, "-ldl")
	}

	if out, e := exec.Command(cc, args...).CombinedOutput(); e != nil {
		t.Fatalf("compile helper protocol: %v\n%s", e, out)
	}

	if out, e := exec.Command(binary, prefix+strings.Repeat("a", 64)).CombinedOutput(); e != nil {
		t.Fatalf("helper protocol: %v\n%s", e, out)
	}
}

func TestNativeProcessCheck(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX helper process check")
	}

	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler unavailable")
	}

	root := t.TempDir()
	binary := filepath.Join(root, "process-test")

	args := []string{"-std=c11", "-D_DEFAULT_SOURCE", "../../helper/process_test.c", "../../helper/log.c", "-o", binary}
	if runtime.GOOS == "linux" {
		args = append(args, "-ldl")
	}

	if out, e := exec.Command(cc, args...).CombinedOutput(); e != nil {
		t.Fatalf("compile helper process check: %v\n%s", e, out)
	}

	if out, e := exec.Command(binary).CombinedOutput(); e != nil {
		t.Fatalf("helper process check: %v\n%s", e, out)
	}
}

func TestNativeBundleVerification(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX helper bundle check")
	}

	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler unavailable")
	}

	root := t.TempDir()
	binary := filepath.Join(root, "bundle-verify-test")
	args := []string{"-std=c11", "-D_DEFAULT_SOURCE", "../../helper/bundle_verify_test.c", "../../helper/bundle_verify.c", "../../helper/log.c", "-o", binary}

	if out, e := exec.Command(cc, args...).CombinedOutput(); e != nil {
		t.Fatalf("compile bundle verification: %v\n%s", e, out)
	}

	if out, e := exec.Command(binary, root).CombinedOutput(); e != nil {
		t.Fatalf("bundle verification: %v\n%s", e, out)
	}
}
