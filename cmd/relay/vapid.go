package main

import (
	"fmt"
	"os"

	"github.com/squaddle-org/relay/internal/webpush"
)

// runVapidCLI is the relay admin CLI for minting a VAPID keypair (ADR-0013): `relay vapid
// generate`. Prints the PEM private key and the base64url public key to stdout exactly once -
// same "never persisted by this process, the operator is responsible for it" posture as
// runVoucherCLI's plaintext voucher code. The private key is what `-vapid-private-key-file`
// reads back in; the public key is only printed for convenience (it's also derivable from the
// private key, and served at runtime via `GET /v1/push/vapid`).
func runVapidCLI(args []string) {
	if len(args) != 1 || args[0] != "generate" {
		fmt.Fprintln(os.Stderr, "usage: relay vapid generate")
		os.Exit(2)
	}

	key, err := webpush.GenerateKeypair()
	if err != nil {
		fmt.Fprintln(os.Stderr, "generating VAPID keypair:", err)
		os.Exit(1)
	}
	pemBytes, err := webpush.EncodePrivateKeyPEM(key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "encoding VAPID private key:", err)
		os.Exit(1)
	}

	fmt.Println("VAPID keypair generated - this private key is never stored by this process, hand it off now:")
	fmt.Print(string(pemBytes))
	fmt.Println("public key (also served at GET /v1/push/vapid once this key is configured):")
	fmt.Println(webpush.PublicKeyBase64URL(&key.PublicKey))
}
