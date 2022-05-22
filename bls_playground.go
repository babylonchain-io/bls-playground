package main

import (
	"fmt"
	"time"

	"github.com/bls-playground/utils"
)

func main() {
	validatorNum := 10
	msg := []byte("hello BBL")

	fmt.Printf("The experiment is with %d validators to sign '%s'\n", validatorNum, msg)

	sks, pubks := utils.GenerateBatchTestKeyPairs(validatorNum)
	sigs := utils.SignMsg(sks, msg)

	aggSig, success := utils.AggSig(sigs)
	if !success {
		fmt.Printf("Aggregation failed")
	}

	fmt.Printf("Length of a secret key is: %d\n", len(sks[0].Serialize()))
	fmt.Printf("Length of a public key is: %d\n", len(pubks[0].Compress()))
	fmt.Printf("Length of a bls signature is: %d\n", len(sigs[0].Compress()))
	fmt.Printf("Length of a multi-sig is: %d\n", len(aggSig.Compress()))

	for i := 0; i < validatorNum; i++ {
		fmt.Printf("[Validator %d] secret key is: %x\n", i, sks[i].Serialize())
		fmt.Printf("[Validator %d] public key is: %x\n", i, pubks[i].Compress())
		fmt.Printf("[Validator %d] bls signature is: %x\n", i, sigs[i].Compress())
	}
	fmt.Printf("The multi-sig is: %x\n", aggSig.Compress())

	startT := time.Now()
	verified := utils.VerifyMultiSig(aggSig, pubks, msg)
	endT := time.Now()
	if verified {
		fmt.Printf("Verification of the multi-sig success! Lasts: %dns\n", endT.Sub(startT).Nanoseconds())
	} else {
		fmt.Printf("Verification of the multi-sig failed! Lasts: %dns\n", endT.Sub(startT).Nanoseconds())
	}
}
