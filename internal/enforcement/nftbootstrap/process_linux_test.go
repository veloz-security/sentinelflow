//go:build linux

package nftbootstrap

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
)

func TestProductionManagerAndCommandsAreFixedOnLinux(t *testing.T) {
	manager, err := NewProductionManager()
	if err != nil || manager == nil || manager.run == nil {
		t.Fatalf("production manager = %#v, %v", manager, err)
	}

	tests := []struct {
		kind processKind
		args []string
		in   []byte
	}{
		{processInventory, inventoryArguments[:], nil},
		{processApply, applyArguments[:], []byte(testBaseContract)},
		{processVerifyLive, verifyArguments[:], nil},
	}
	for _, test := range tests {
		request := processRequest{kind: test.kind, stdin: append([]byte(nil), test.in...)}
		command := newProductionCommand(context.Background(), request)
		if command.Path != "/usr/sbin/nft" || command.Dir != "/" ||
			fmt.Sprint(command.Args) != fmt.Sprint(append([]string{"/usr/sbin/nft"}, test.args...)) ||
			fmt.Sprint(command.Env) != fmt.Sprint([]string{"LANG=C", "LC_ALL=C"}) ||
			len(command.ExtraFiles) != 0 {
			t.Fatalf("command drifted: path=%q args=%v dir=%q env=%v extra=%d",
				command.Path, command.Args, command.Dir, command.Env, len(command.ExtraFiles))
		}
		if test.kind == processApply {
			stdin, readErr := io.ReadAll(command.Stdin)
			if readErr != nil || !bytes.Equal(stdin, test.in) {
				t.Fatalf("apply stdin = %q, %v", stdin, readErr)
			}
		} else if command.Stdin != nil {
			t.Fatalf("read-only command received stdin: %#v", command.Stdin)
		}
	}
}
