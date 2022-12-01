package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/abstractions"
	"github.com/tendermint/tendermint/crypto/pedersen"
	"github.com/tendermint/tendermint/crypto/tmhash"
	ctest "github.com/tendermint/tendermint/internal/libs/test"
	tmrand "github.com/tendermint/tendermint/libs/rand"
)

type testItem []byte

func (tI testItem) Hash() []byte {
	return []byte(tI)
}

func TestCompareCairo1(t *testing.T) {

	a0 := append(make([]byte, 31), []byte{05}...)
	a1 := append(make([]byte, 31), []byte{10}...)
	a2 := append(make([]byte, 31), []byte{15}...)
	a3 := append(make([]byte, 31), []byte{20}...)

	a := [][]byte{a0, a1, a2, a3}
	b := big.NewInt(0).SetBytes(HashFromByteSlicesFelt(a))
	c, _ := big.NewInt(0).SetString("2043067667429007109707167030739757236652130480385428815029361838610821293657", 10)
	require.Equal(t, c.Cmp(b), 0)
}

func TestCompareCairo2(t *testing.T) {

	a0, _ := big.NewInt(0).SetString("3454952438923234006568527143781167235276775604066827568425481679972150643448", 10)
	b0 := pedersen.ByteRounderInt128(a0.Bytes())
	a1, _ := big.NewInt(0).SetString("2494110571235400288533148571502202163537425285881062150149675116686078062864", 10)
	b1 := pedersen.ByteRounderInt128(a1.Bytes())
	a2, _ := big.NewInt(0).SetString("2908682032041418908903105681227249033483541201006723240850136728317167492227", 10)
	b2 := pedersen.ByteRounderInt128(a2.Bytes())
	a3, _ := big.NewInt(0).SetString("2599929233293119982501280579193581206158611315304505534385243879518502888628", 10)
	b3 := pedersen.ByteRounderInt128(a3.Bytes())
	a4, _ := big.NewInt(0).SetString("2206723481920075052107131543171542739217923834753038471674523378436884433248", 10)
	b4 := pedersen.ByteRounderInt128(a4.Bytes())
	a5, _ := big.NewInt(0).SetString("3196042820007611016667731428007167809703393661030333042255511753651389202253", 10)
	b5 := pedersen.ByteRounderInt128(a5.Bytes())
	a6, _ := big.NewInt(0).SetString("2089986280348253421170679821480865132823066470938446095505822317253594081284", 10)
	b6 := pedersen.ByteRounderInt128(a6.Bytes())
	a7, _ := big.NewInt(0).SetString("3081086906630340236863811480373298036427706612523827020334484978388108542248", 10)
	b7 := pedersen.ByteRounderInt128(a7.Bytes())
	a8, _ := big.NewInt(0).SetString("3081086906630340236863811480373298036427706612523827020334484978388108542248", 10)
	b8 := pedersen.ByteRounderInt128(a8.Bytes())
	a9, _ := big.NewInt(0).SetString("2132461975834504200398180281070409533541683498016798668455504133351250391630", 10)
	b9 := pedersen.ByteRounderInt128(a9.Bytes())
	// a10, _ := big.NewInt(0).SetString("0", 10)
	b10 := make([]byte, 32)
	a11, _ := big.NewInt(0).SetString("2089986280348253421170679821480865132823066470938446095505822317253594081284", 10)
	b11 := pedersen.ByteRounderInt128(a11.Bytes())
	a12, _ := big.NewInt(0).SetString("2089986280348253421170679821480865132823066470938446095505822317253594081284", 10)
	b12 := pedersen.ByteRounderInt128(a12.Bytes())
	a13, _ := big.NewInt(0).SetString("2096651760584687198361717080648350102473644945561758734773364314748439283675", 10)
	b13 := pedersen.ByteRounderInt128(a13.Bytes())

	c := [][]byte{b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13}
	d := big.NewInt(0).SetBytes(HashFromByteSlicesFelt(c))
	e, _ := big.NewInt(0).SetString("1887775195007575006484085469099927140850376562514962098842400547226481521", 10)
	require.Equal(t, e.Cmp(d), 0)
}

func TestHashFromByteSlices(t *testing.T) {
	testcases := map[string]struct {
		slices     [][]byte
		expectHash string // in hex format
	}{
		//"nil":          {nil, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		//"empty":        {[][]byte{}, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		//"single":       {[][]byte{{1, 2, 3}}, "054edec1d0211f624fed0cbca9d4f9400b0e491c43742af2c5b0abebf0c990d8"},
		//"single blank": {[][]byte{{}}, "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"},
		//"two":          {[][]byte{{1, 2, 3}, {4, 5, 6}}, "82e6cfce00453804379b53962939eaa7906b39904be0813fcadd31b100773c4b"},
		// "many": {
		// 	[][]byte{{1, 2}, {3, 4}, {5, 6}, {7, 8}, {9, 10}},
		// 	"f326493eceab4f2d9ffbc78c59432a0a005d6ea98392045c74df5d14a113be18",
		// },
	}
	for name, tc := range testcases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			hash := HashFromByteSlicesInt128(tc.slices)
			assert.Equal(t, tc.expectHash, hex.EncodeToString(hash))
		})
	}
}

func TestProof(t *testing.T) {

	// Try an empty proof first
	rootHash, proofs := ProofsFromByteSlicesInt128([][]byte{})
	// require.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hex.EncodeToString(rootHash))
	require.Empty(t, proofs)

	total := 100

	items := make([][]byte, total)
	for i := 0; i < total; i++ {
		items[i] = testItem(tmrand.Bytes(tmhash.Size))
	}

	rootHash = HashFromByteSlicesInt128(items)

	rootHash2, proofs := ProofsFromByteSlicesInt128(items)

	require.Equal(t, rootHash, rootHash2, "Unmatched root hashes: %X vs %X", rootHash, rootHash2)

	// For each item, check the trail.
	for i, item := range items {
		proof := proofs[i]

		// Check total/index
		require.EqualValues(t, proof.Index, i, "Unmatched indicies: %d vs %d", proof.Index, i)

		require.EqualValues(t, proof.Total, total, "Unmatched totals: %d vs %d", proof.Total, total)

		// Verify success
		err := proof.VerifyInt128(rootHash, item)
		require.NoError(t, err, "Verification failed: %v.", err)

		// Trail too long should make it fail
		origAunts := proof.Aunts
		proof.Aunts = append(proof.Aunts, tmrand.Bytes(32))
		err = proof.VerifyInt128(rootHash, item)
		require.Error(t, err, "Expected verification to fail for wrong trail length")

		proof.Aunts = origAunts

		// Trail too short should make it fail
		proof.Aunts = proof.Aunts[0 : len(proof.Aunts)-1]
		err = proof.VerifyInt128(rootHash, item)
		require.Error(t, err, "Expected verification to fail for wrong trail length")

		proof.Aunts = origAunts

		// Mutating the itemHash should make it fail.
		err = proof.VerifyInt128(rootHash, ctest.MutateByteSlice(item))
		require.Error(t, err, "Expected verification to fail for mutated leaf hash")

		// Mutating the rootHash should make it fail.
		err = proof.VerifyInt128(ctest.MutateByteSlice(rootHash), item)
		require.Error(t, err, "Expected verification to fail for mutated root hash")
	}
}

func TestHashAlternatives(t *testing.T) {

	total := 104

	items := make([][]byte, total)
	for i := 0; i < total; i++ {
		items[i] = testItem(tmrand.Bytes(tmhash.Size))
	}

	rootHash1 := HashFromByteSlicesIterative(items)
	rootHash2 := HashFromByteSlicesInt128(items)
	require.Equal(t, rootHash1, rootHash2, "Unmatched root hashes: %X vs %X", rootHash1, rootHash2)
}

func BenchmarkHashAlternatives(b *testing.B) {
	total := 100

	items := make([][]byte, total)
	for i := 0; i < total; i++ {
		items[i] = testItem(tmrand.Bytes(tmhash.Size))
	}

	b.ResetTimer()
	b.Run("recursive", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = HashFromByteSlicesInt128(items)
		}
	})

	b.Run("iterative", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = HashFromByteSlicesIterative(items)
		}
	})
}

func Test_getSplitPoint(t *testing.T) {
	tests := []struct {
		length int64
		want   int64
	}{
		{1, 0},
		{2, 1},
		{3, 2},
		{4, 2},
		{5, 4},
		{10, 8},
		{20, 16},
		{100, 64},
		{255, 128},
		{256, 128},
		{257, 256},
	}
	for _, tt := range tests {
		got := getSplitPoint(tt.length)
		require.EqualValues(t, tt.want, got, "getSplitPoint(%d) = %v, want %v", tt.length, got, tt.want)
	}
}

func TestPedersen(t *testing.T) {
	total := 10000

	items := make([]byte, total)

	start := time.Now()

	crypto.ChecksumInt128(items)

	elapsed := time.Since(start)
	fmt.Println("elapsed time", elapsed)
	return

}

func TestSha(t *testing.T) {
	total := 1000000000

	items := make([]byte, total)

	start := time.Now()

	sha256.Sum256(items)

	elapsed := time.Since(start)
	fmt.Println("elapsed time", elapsed)
	return

}

func TestTreePedersen(t *testing.T) {
	total := 100

	items := make([][]byte, total)

	start := time.Now()

	HashFromByteSlicesInt128(items)

	elapsed := time.Since(start)
	fmt.Println("elapsed time", elapsed)
	return

}
