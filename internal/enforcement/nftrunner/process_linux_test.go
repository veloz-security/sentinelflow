//go:build linux

package nftrunner

import "testing"

func TestProductionRunnerIsFixedOnLinux(t *testing.T) {
	runner, err := NewProductionRunner()
	if err != nil || runner == nil || runner.run == nil {
		t.Fatalf("production runner = %#v, %v", runner, err)
	}
	if (processRequest{kind: processMutation}).path() != "/usr/sbin/nft" ||
		(processRequest{kind: processInspect}).path() != "/usr/sbin/nft" {
		t.Fatal("production path drifted")
	}
}
