package bls

import "testing"

// BenchmarkSignMsg benchmarks the BLS signing time
func BenchmarkSignMsg(b *testing.B) {
	n := 1
	msg := []byte("hello Babylon")
	sks, _ := GenerateBatchTestKeyPairs(n)
	for i := 0; i < b.N; i++ {
		_ = SignMsg(sks, msg)
	}
}

// BenchmarkAggSig benchmarks the BLS aggregating time
func BenchmarkAggSig(b *testing.B) {
	n := 67
	msg := []byte("hello Babylon")
	sks, _ := GenerateBatchTestKeyPairs(n)
	sigs := SignMsg(sks, msg)
	for i := 0; i < b.N; i++ {
		_, _ = AggSig(sigs)
	}
}

// BenchmarkVerifyMultiSig benchmarks the BLS verifying time
// note that there's no difference between verifying a single
// BLS signature vs. a multi-signature with a single public
// key that is aggregated
func BenchmarkVerifyMultiSig(b *testing.B) {
	n := 1
	msg := []byte("hello Babylon")
	sks, pks := GenerateBatchTestKeyPairs(n)
	sigs := SignMsg(sks, msg)
	for i := 0; i < b.N; i++ {
		_ = VerifyMultiSig(sigs[0], pks, msg)
	}
}
